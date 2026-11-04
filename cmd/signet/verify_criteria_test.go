package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/sigid"
	"github.com/spf13/cobra"
)

// signet-be49b9: notme task certs carry a criteria extension (.1.10), and
// notme refuses a misfit both at mint and in its own `task-cert verify`.
// `signet verify` did not look at it, so a task that broke its criteria --
// a legacy task shown with a tier that grants criteria, a criteria the tier
// never granted, a 301 s agent-session, a scope over the ceiling, a
// tier-minted deploy/1 -- reported "Certificate valid".
//
// The golden fixtures in testdata/criteria were minted by notme's OWN code
// (worker/src/cert-authority.ts, scripts/task-cert/lib.ts; generator:
// testdata/criteria/gen-criteria-fixtures.mts), and manifest.json records
// notme's OWN verdict for each one (verifyChain, or checkCriteria for an
// authority-issued leaf). Every case must come out of signet verify with
// the same verdict and the same reason string.

type criteriaFixture struct {
	Name   string  `json:"name"`
	Tier   *string `json:"tier"`
	Cutoff *string `json:"cutoff"`
	How    string  `json:"how"`
	Notme  struct {
		OK       bool    `json:"ok"`
		Criteria *string `json:"criteria"`
		Legacy   bool    `json:"legacy"`
		Reason   string  `json:"reason"`
	} `json:"notme"`
}

type criteriaManifest struct {
	At    time.Time         `json:"at"`
	Cases []criteriaFixture `json:"cases"`
}

func loadCriteriaManifest(t *testing.T) (criteriaManifest, string) {
	t.Helper()
	dir := filepath.Join("testdata", "criteria")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json")) // #nosec G304 -- fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var m criteriaManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) < 20 {
		t.Fatalf("manifest has %d cases, want the full set", len(m.Cases))
	}
	return m, dir
}

func runCriteriaFixture(t *testing.T, m criteriaManifest, dir string, c criteriaFixture) (string, error) {
	t.Helper()
	opts := verifyOptions{
		caPath:  filepath.Join(dir, "root.cert"),
		offline: true, // the fixtures' epoch has no live authority; criteria is offline by nature
		at:      m.At,
	}
	if c.Cutoff != nil {
		cut, err := sigid.ParseLegacyCutoff(*c.Cutoff)
		if err != nil {
			t.Fatal(err)
		}
		opts.legacyCutoff = cut
	}
	var out bytes.Buffer
	err := verifyAndReport(context.Background(), &out, filepath.Join(dir, c.Name+".cert"), opts)
	return out.String(), err
}

func wantCriteriaLine(c criteriaFixture) string {
	switch {
	case !c.Notme.OK:
		return "Criteria:  refused: " + c.Notme.Reason
	case c.Notme.Legacy:
		return "Criteria:  none (legacy: issued under a pre-criteria tier)"
	case c.Tier == nil:
		return "Criteria:  " + *c.Notme.Criteria + " (authority-minted)"
	default:
		return "Criteria:  " + *c.Notme.Criteria + " (within tier grant)"
	}
}

func TestVerifyCriteria_GoldenNotmeFixtures(t *testing.T) {
	m, dir := loadCriteriaManifest(t)
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			out, err := runCriteriaFixture(t, m, dir, c)
			if c.Notme.OK && err != nil {
				t.Fatalf("notme accepts (%s), signet refused: %v\n%s", c.How, err, out)
			}
			if !c.Notme.OK {
				if err == nil {
					t.Fatalf("notme refuses %q (%s), signet verify accepted:\n%s", c.Notme.Reason, c.How, out)
				}
				if !strings.Contains(err.Error(), "criteria: "+c.Notme.Reason) {
					t.Fatalf("error = %v, want notme's reason %q", err, c.Notme.Reason)
				}
			}
			if want := wantCriteriaLine(c); !strings.Contains(out, want) {
				t.Fatalf("output lacks %q:\n%s", want, out)
			}
		})
	}
}

// Every refusal must come from the criteria rules, not from the chain: each
// fixture's chain verifies at its mint time.
func TestVerifyCriteria_FixtureChainsVerify(t *testing.T) {
	m, dir := loadCriteriaManifest(t)
	for _, c := range m.Cases {
		r, err := verifyCertAt(filepath.Join(dir, c.Name+".cert"), filepath.Join(dir, "root.cert"), m.At)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if !r.Valid {
			t.Errorf("%s: chain does not verify at %s: %s", c.Name, m.At, r.Reason)
		}
	}
}

// The passing case, end to end, as an operator reads it.
func TestVerifyCriteria_AgentSessionOutput(t *testing.T) {
	m, dir := loadCriteriaManifest(t)
	for _, c := range m.Cases {
		if c.Name != "agent-session-ok" {
			continue
		}
		out, err := runCriteriaFixture(t, m, dir, c)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Certificate valid", "Criteria:  agent-session/1 (within tier grant)"} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
		return
	}
	t.Fatal("no agent-session-ok fixture")
}

// Criteria is checked before revocation: a misfit is refused without
// touching the network (the authority here is unreachable).
func TestVerifyCriteria_RefusedBeforeRevocation(t *testing.T) {
	m, dir := loadCriteriaManifest(t)
	var out bytes.Buffer
	err := verifyAndReport(context.Background(), &out, filepath.Join(dir, "lifetime-over.cert"), verifyOptions{
		caPath:    filepath.Join(dir, "root.cert"),
		authority: "https://127.0.0.1:1",
		at:        m.At,
	})
	if err == nil || !strings.Contains(err.Error(), "criteria: agent-session/1 allows at most 300s, this certificate spans 301s") {
		t.Fatalf("err = %v\n%s", err, out.String())
	}
	if strings.Contains(err.Error(), "revocation") {
		t.Fatalf("revocation ran on a criteria misfit: %v", err)
	}
}

// A legacy notme task (no .1.10 anywhere in the chain) is accepted until the
// operator's cutoff, and refused after it -- with a fresh chain, at the wall
// clock, the way an operator runs it.
func TestVerifyCriteria_LegacyCutoffLiveChain(t *testing.T) {
	c := newNotmeChain(t)
	dir := t.TempDir()
	rootPath := writeFile(t, dir, "root.pem", c.rootPEM)
	chainPath := writeFile(t, dir, "chain.pem", c.taskPEM, c.tierPEM)

	run := func(cutoff *time.Time) (string, error) {
		var out bytes.Buffer
		err := verifyAndReport(context.Background(), &out, chainPath, verifyOptions{caPath: rootPath, offline: true, legacyCutoff: cutoff})
		return out.String(), err
	}

	out, err := run(nil)
	if err != nil || !strings.Contains(out, "Criteria:  none (legacy: issued under a pre-criteria tier)") {
		t.Fatalf("no cutoff: err=%v\n%s", err, out)
	}
	future := time.Now().Add(24 * time.Hour)
	if out, err := run(&future); err != nil {
		t.Fatalf("cutoff tomorrow: %v\n%s", err, out)
	}
	past := time.Now().Add(-24 * time.Hour)
	out, err = run(&past)
	if err == nil || !strings.Contains(err.Error(), "criteria: legacy certificate past the operator's cutoff") {
		t.Fatalf("cutoff yesterday: err=%v\n%s", err, out)
	}
}

// A certificate from signet's own authority (no notme profile, no .1.10) is
// not a notme task: no Criteria line, and a cutoff does not touch it.
//
// Nor is a notme bridge certificate the authority issues directly (no tier,
// no .1.10, e.g. /cert/gha): notme's task-cert verify only ever judges a
// task under a tier, and the legacy cutoff phases out pre-criteria TASKS.
func TestVerifyCriteria_NonTaskCertsUntouched(t *testing.T) {
	signetCert, signetCA := createTestCertFiles(t, "user@example.com", "github-12345", 10*time.Minute)
	notmeCert, notmeCA := notmeStyleCertFiles(t, "gha-oidc")
	past := time.Now().Add(-24 * time.Hour)
	for name, p := range map[string][2]string{"signet": {signetCert, signetCA}, "notme bridge": {notmeCert, notmeCA}} {
		var out bytes.Buffer
		err := verifyAndReport(context.Background(), &out, p[0], verifyOptions{caPath: p[1], offline: true, legacyCutoff: &past})
		if err != nil {
			t.Fatalf("%s cert refused: %v\n%s", name, err, out.String())
		}
		if strings.Contains(out.String(), "Criteria:") {
			t.Fatalf("Criteria line on a %s cert:\n%s", name, out.String())
		}
	}
}

// --legacy-cutoff and NOTME_LEGACY_CUTOFF resolve as notme's task-cert verify
// resolves them: the flag wins, an empty flag is an error, an empty env var
// is unset, anything but an ISO date is an error.
func TestVerifyLegacyCutoffFlagAndEnv(t *testing.T) {
	newCmd := func() *cobra.Command {
		c := &cobra.Command{Use: "verify"}
		c.Flags().String("legacy-cutoff", "", "")
		return c
	}

	t.Setenv("NOTME_LEGACY_CUTOFF", "2026-12-01")
	got, err := verifyLegacyCutoff(newCmd())
	if err != nil || got == nil || !got.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("env: %v %v", got, err)
	}

	c := newCmd()
	if err := c.Flags().Set("legacy-cutoff", "2027-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	got, err = verifyLegacyCutoff(c)
	if err != nil || got == nil || !got.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("flag over env: %v %v", got, err)
	}

	c = newCmd()
	if err := c.Flags().Set("legacy-cutoff", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyLegacyCutoff(c); err == nil || !strings.Contains(err.Error(), "--legacy-cutoff needs a value") {
		t.Fatalf("empty flag: %v", err)
	}

	t.Setenv("NOTME_LEGACY_CUTOFF", "")
	if got, err := verifyLegacyCutoff(newCmd()); err != nil || got != nil {
		t.Fatalf("empty env: %v %v", got, err)
	}

	t.Setenv("NOTME_LEGACY_CUTOFF", "next week")
	if _, err := verifyLegacyCutoff(newCmd()); err == nil || !strings.Contains(err.Error(), "is not an ISO date") {
		t.Fatalf("bad env: %v", err)
	}
}
