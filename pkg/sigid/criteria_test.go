package sigid

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// signet-be49b9: notme's .1.10 criteria rules, ported from notme
// worker/src/__tests__/criteria.test.ts. The reasons are notme's own strings,
// byte for byte: signet verify must refuse what notme's task-cert verify
// refuses, for the same reason.

var critT0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

var (
	csAS  = Criteria{Name: "agent-session", Version: 1}
	csLLO = Criteria{Name: "llo-run", Version: 1}
	csDEP = Criteria{Name: "deploy", Version: 1}
)

// DER helpers mirroring the TypeScript test's derTlv / elem / seq.
func tlv(tag byte, body []byte) []byte {
	n := len(body)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, body...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
}

func utf8s(s string) []byte { return tlv(0x0c, []byte(s)) }

func elem(name string, version []byte) []byte {
	return tlv(0x30, append(utf8s(name), tlv(0x02, version)...))
}

func seq(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return tlv(0x30, b)
}

func scopesDER(scopes ...string) []byte {
	parts := make([][]byte, 0, len(scopes))
	for _, s := range scopes {
		parts = append(parts, utf8s(s))
	}
	return seq(parts...)
}

func encodeCriteriaForTest(t *testing.T, list ...Criteria) []byte {
	t.Helper()
	der, err := EncodeCriteria(list)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type certSpec struct {
	spanS       int64
	criteria    []byte // raw .1.10 value; nil = absent
	scopes      []byte // raw .1.3 value; nil = absent
	confinement bool
}

var critKey = func() ed25519.PrivateKey {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return k
}()

func mk(t *testing.T, s certSpec) *x509.Certificate {
	t.Helper()
	span := s.spanS
	if span == 0 {
		span = 300
	}
	var exts []pkix.Extension
	if s.criteria != nil {
		exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier(OIDCriteria), Value: s.criteria})
	}
	if s.scopes != nil {
		exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier(OIDNotmeScopes), Value: s.scopes})
	}
	if s.confinement {
		exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier(OIDConfinementDigest), Value: []byte{0x04, 0x01, 0x00}})
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "test"},
		NotBefore:       critT0,
		NotAfter:        critT0.Add(time.Duration(span) * time.Second),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, critKey.Public(), critKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func withCriteria(t *testing.T, list ...Criteria) certSpec {
	return certSpec{criteria: encodeCriteriaForTest(t, list...)}
}

func refusedWith(t *testing.T, v CriteriaVerdict, reason string) {
	t.Helper()
	if v.OK || v.Reason != reason {
		t.Fatalf("verdict = %+v, want refused with %q", v, reason)
	}
}

func acceptedAs(t *testing.T, v CriteriaVerdict, want *Criteria, legacy bool) {
	t.Helper()
	if !v.OK {
		t.Fatalf("refused: %q, want accepted", v.Reason)
	}
	if v.Legacy != legacy {
		t.Fatalf("legacy = %v, want %v", v.Legacy, legacy)
	}
	switch {
	case want == nil && v.Criteria != nil:
		t.Fatalf("criteria = %v, want none", *v.Criteria)
	case want != nil && (v.Criteria == nil || *v.Criteria != *want):
		t.Fatalf("criteria = %v, want %v", v.Criteria, *want)
	}
}

func TestCriteriaEncodeRead(t *testing.T) {
	der := encodeCriteriaForTest(t, csAS)
	if len(der) < 5 || der[0] != 0x30 || der[2] != 0x30 || der[4] != 0x0c || int(der[3]) != 2+len("agent-session")+3 {
		t.Fatalf("unexpected DER shape % x", der)
	}
	list, present, ok := ReadCriteria(mk(t, withCriteria(t, csAS)))
	if !present || !ok || len(list) != 1 || list[0] != csAS {
		t.Fatalf("read = %v %v %v", list, present, ok)
	}
	three := []Criteria{csAS, csLLO, csDEP}
	list, _, ok = ReadCriteria(mk(t, withCriteria(t, three...)))
	if !ok || len(list) != 3 || list[0] != csAS || list[1] != csLLO || list[2] != csDEP {
		t.Fatalf("three = %v %v", list, ok)
	}
	if _, present, _ := ReadCriteria(mk(t, certSpec{})); present {
		t.Fatal("absent .1.10 read as present")
	}
	if _, err := EncodeCriteria(nil); err == nil {
		t.Fatal("empty list encoded")
	}
	if _, err := EncodeCriteria([]Criteria{csAS, csAS}); err == nil {
		t.Fatal("duplicate list encoded")
	}
}

func TestCriteriaAcceptsLongFormLengths(t *testing.T) {
	e := elem("agent-session", []byte{1})
	inner := append([]byte{0x30, 0x81, byte(len(e) - 2)}, e[2:]...)
	outer := append([]byte{0x30, 0x81, byte(len(inner))}, inner...)
	list, present, ok := ReadCriteria(mk(t, certSpec{criteria: outer}))
	if !present || !ok || len(list) != 1 || list[0] != csAS {
		t.Fatalf("long-form = %v %v %v", list, present, ok)
	}
}

func TestParseCriteriaID(t *testing.T) {
	if c, ok := ParseCriteriaID("agent-session/1"); !ok || c != csAS {
		t.Fatalf("parse = %v %v", c, ok)
	}
	if csAS.ID() != "agent-session/1" {
		t.Fatalf("ID = %q", csAS.ID())
	}
	for _, bad := range []string{"", "agent-session", "/1", "a/", "a/0", "a/-1", "a/1/2", "a/x", "a/01", "a/99999999999"} {
		if _, ok := ParseCriteriaID(bad); ok {
			t.Errorf("ParseCriteriaID(%q) accepted", bad)
		}
	}
}

func TestCriteriaMalformedNeverPasses(t *testing.T) {
	good := elem("agent-session", []byte{1})
	cases := map[string][]byte{
		"zero elements":              seq(),
		"wrong outer tag":            tlv(0x31, good),
		"wrong element tag":          seq(tlv(0x31, good[2:])),
		"name not utf8 string":       seq(tlv(0x30, append(tlv(0x04, []byte{97}), tlv(0x02, []byte{1})...))),
		"name invalid utf-8":         seq(tlv(0x30, append(tlv(0x0c, []byte{0xff, 0xfe}), tlv(0x02, []byte{1})...))),
		"name with slash":            seq(elem("agent-session/1", []byte{1})),
		"version not integer":        seq(tlv(0x30, append(utf8s("agent-session"), tlv(0x04, []byte{1})...))),
		"trailing bytes in element":  seq(tlv(0x30, append(append(utf8s("agent-session"), tlv(0x02, []byte{1})...), 0x00))),
		"trailing bytes after outer": append(seq(good), 0x00),
		"negative integer":           seq(elem("agent-session", []byte{0xff})),
		"zero integer":               seq(elem("agent-session", []byte{0})),
		"non-minimal integer":        seq(elem("agent-session", []byte{0, 1})),
		"oversize integer":           seq(elem("agent-session", []byte{1, 0, 0, 0, 0})),
		"empty integer":              seq(elem("agent-session", []byte{})),
		"truncated":                  seq(good)[:8],
		"length overruns":            {0x30, 0x20, 0x30, 0x03},
		"empty value":                {},
		"indefinite length":          {0x30, 0x80, 0x00, 0x00},
		"empty name":                 seq(elem("", []byte{1})),
		"duplicate":                  seq(good, good),
	}
	for label, der := range cases {
		t.Run(label, func(t *testing.T) {
			leaf := mk(t, certSpec{criteria: der})
			if _, present, ok := ReadCriteria(leaf); !present || ok {
				t.Fatalf("read present=%v ok=%v, want present and malformed", present, ok)
			}
			refusedWith(t, CheckCriteria(nil, leaf, CriteriaOptions{At: critT0}), "malformed criteria on leaf")
		})
	}
}

func TestCriteriaMalformedTierNamedFirst(t *testing.T) {
	tier := mk(t, certSpec{criteria: seq()})
	leaf := mk(t, certSpec{criteria: seq()})
	refusedWith(t, CheckCriteria(tier, leaf, CriteriaOptions{At: critT0}), "malformed criteria on tier")
}

func TestCriteriaTwoOnATask(t *testing.T) {
	refusedWith(t, CheckCriteria(mk(t, withCriteria(t, csAS, csLLO)), mk(t, withCriteria(t, csAS, csLLO)), CriteriaOptions{}),
		"a task carries exactly one criteria")
}

func TestCriteriaUnknown(t *testing.T) {
	nope := Criteria{Name: "nope", Version: 1}
	as2 := Criteria{Name: "agent-session", Version: 2}
	tier := mk(t, withCriteria(t, nope, as2))
	for _, c := range []Criteria{nope, as2} {
		refusedWith(t, CheckCriteria(tier, mk(t, withCriteria(t, c)), CriteriaOptions{}), "unknown criteria "+c.ID())
	}
	mystery := Criteria{Name: "mystery", Version: 3}
	refusedWith(t, CheckCriteria(mk(t, withCriteria(t, mystery)), mk(t, withCriteria(t, mystery)), CriteriaOptions{}),
		"unknown criteria mystery/3")
}

func TestCriteriaLegacy(t *testing.T) {
	acceptedAs(t, CheckCriteria(mk(t, certSpec{}), mk(t, certSpec{}), CriteriaOptions{At: critT0}), nil, true)

	at := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	past := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	future := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	refusedWith(t, CheckCriteria(mk(t, certSpec{}), mk(t, certSpec{}), CriteriaOptions{At: at, LegacyCutoff: &past}),
		"legacy certificate past the operator's cutoff")
	acceptedAs(t, CheckCriteria(mk(t, certSpec{}), mk(t, certSpec{}), CriteriaOptions{At: at, LegacyCutoff: &future}), nil, true)
	// The comparison is strict: a check AT the cutoff is still before it.
	acceptedAs(t, CheckCriteria(mk(t, certSpec{}), mk(t, certSpec{}), CriteriaOptions{At: at, LegacyCutoff: &at}), nil, true)
	// A cutoff never touches a certificate that carries criteria.
	acceptedAs(t, CheckCriteria(mk(t, withCriteria(t, csAS)), mk(t, withCriteria(t, csAS)), CriteriaOptions{At: at, LegacyCutoff: &past}), &csAS, false)
}

func TestCriteriaTaskClaimsWithoutTier(t *testing.T) {
	refusedWith(t, CheckCriteria(mk(t, certSpec{}), mk(t, withCriteria(t, csAS)), CriteriaOptions{}),
		"task claims criteria its tier does not carry")
}

func TestCriteriaTierCarriesTaskNone(t *testing.T) {
	refusedWith(t, CheckCriteria(mk(t, withCriteria(t, csAS)), mk(t, certSpec{}), CriteriaOptions{}),
		"tier carries criteria; the task names none")
}

func TestCriteriaMintedBy(t *testing.T) {
	refusedWith(t, CheckCriteria(nil, mk(t, withCriteria(t, csAS)), CriteriaOptions{}), "agent-session/1 is minted by the tier only")
	refusedWith(t, CheckCriteria(mk(t, withCriteria(t, csDEP)), mk(t, withCriteria(t, csDEP)), CriteriaOptions{}),
		"deploy/1 is minted by the authority only")
}

func TestCriteriaNotGranted(t *testing.T) {
	refusedWith(t, CheckCriteria(mk(t, withCriteria(t, csLLO)), mk(t, withCriteria(t, csAS)), CriteriaOptions{}),
		"task criteria agent-session/1 is not granted by its tier")
}

func TestCriteriaLifetime(t *testing.T) {
	tier := mk(t, withCriteria(t, csAS))
	at := func(span int64) certSpec { s := withCriteria(t, csAS); s.spanS = span; return s }
	acceptedAs(t, CheckCriteria(tier, mk(t, at(300)), CriteriaOptions{}), &csAS, false)
	refusedWith(t, CheckCriteria(tier, mk(t, at(301)), CriteriaOptions{}), "agent-session/1 allows at most 300s, this certificate spans 301s")

	dep := func(span int64) certSpec { s := withCriteria(t, csDEP); s.spanS = span; return s }
	refusedWith(t, CheckCriteria(nil, mk(t, dep(3*3600)), CriteriaOptions{}), "deploy/1 allows at most 900s, this certificate spans 10800s")
	acceptedAs(t, CheckCriteria(nil, mk(t, dep(900)), CriteriaOptions{}), &csDEP, false)

	// Lifetime is read from the certificate, never the wall clock.
	acceptedAs(t, CheckCriteria(tier, mk(t, at(300)), CriteriaOptions{At: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}), &csAS, false)
}

func TestCriteriaScopeCeiling(t *testing.T) {
	tier := mk(t, withCriteria(t, csAS))
	sc := func(c Criteria, der []byte) certSpec { s := withCriteria(t, c); s.scopes = der; return s }
	refusedWith(t, CheckCriteria(tier, mk(t, sc(csAS, scopesDER("bridgeCert", "certMint"))), CriteriaOptions{}),
		"agent-session/1 does not allow scope certMint")
	acceptedAs(t, CheckCriteria(tier, mk(t, sc(csAS, scopesDER("bridgeCert", "sign:git", "sign:attestation"))), CriteriaOptions{}), &csAS, false)
	refusedWith(t, CheckCriteria(nil, mk(t, sc(csDEP, scopesDER("sign:git"))), CriteriaOptions{}), "deploy/1 does not allow scope sign:git")
	llo := sc(csLLO, scopesDER("bridgeCert", "sign:git"))
	llo.confinement = true
	refusedWith(t, CheckCriteria(mk(t, withCriteria(t, csLLO)), mk(t, llo), CriteriaOptions{}), "llo-run/1 does not allow scope sign:git")
}

func TestCriteriaMalformedScopesRefused(t *testing.T) {
	tier := mk(t, withCriteria(t, csAS))
	sc := func(der []byte) certSpec { s := withCriteria(t, csAS); s.scopes = der; return s }
	bridge := utf8s("bridgeCert")
	vectors := map[string][]byte{
		"octet string":                  {0x04, 0x01, 0x00},
		"non-utf8string element":        seq([]byte{0x02, 0x01, 0x01}),
		"truncated element":             {0x30, 0x05, 0x0c, 0x0a, 0x62, 0x72, 0x69},
		"truncated header":              {0x30, 0x01, 0x0c},
		"overlong SEQUENCE length":      append([]byte{0x30, 0x7f}, bridge...),
		"overlong long-form length":     append([]byte{0x30, 0x82, 0x01, 0x00}, bridge...),
		"trailing bytes":                append(scopesDER("bridgeCert"), utf8s("sign:git")...),
		"element overruns its SEQUENCE": append([]byte{0x30, 0x02}, bridge...),
	}
	for name, der := range vectors {
		t.Run(name, func(t *testing.T) {
			refusedWith(t, CheckCriteria(tier, mk(t, sc(der)), CriteriaOptions{}), "malformed scopes on leaf")
		})
	}
	// An absent .1.3 carries no scopes.
	acceptedAs(t, CheckCriteria(tier, mk(t, withCriteria(t, csAS)), CriteriaOptions{}), &csAS, false)
	// A long but well-formed scope list is read, then held to the ceiling.
	refusedWith(t, CheckCriteria(tier, mk(t, sc(scopesDER(strings.Repeat("x", 200)))), CriteriaOptions{}),
		"agent-session/1 does not allow scope "+strings.Repeat("x", 200))
}

func TestCriteriaLLORunRequiresConfinementDigest(t *testing.T) {
	tier := mk(t, withCriteria(t, csLLO))
	refusedWith(t, CheckCriteria(tier, mk(t, withCriteria(t, csLLO)), CriteriaOptions{}), "llo-run/1 requires the run's confinementDigest (.1.7)")
	s := withCriteria(t, csLLO)
	s.confinement = true
	acceptedAs(t, CheckCriteria(tier, mk(t, s), CriteriaOptions{}), &csLLO, false)
}

func TestCriteriaTierMayCarrySeveral(t *testing.T) {
	acceptedAs(t, CheckCriteria(mk(t, withCriteria(t, csAS, csLLO)), mk(t, withCriteria(t, csAS)), CriteriaOptions{}), &csAS, false)
}

func TestCriteriaRegistry(t *testing.T) {
	ids := CriteriaIDs()
	if strings.Join(ids, ",") != "agent-session/1,deploy/1,llo-run/1" {
		t.Fatalf("registry = %v", ids)
	}
	as, _ := LookupCriteria("agent-session/1")
	if as.MintedBy != MintedByTier || as.MaxLifetimeS != 300 || as.RequiresConfinementDigest || !as.Grantable ||
		strings.Join(as.ScopeCeiling, ",") != "bridgeCert,sign:git,sign:attestation" {
		t.Fatalf("agent-session/1 = %+v", as)
	}
	llo, _ := LookupCriteria("llo-run/1")
	if llo.MintedBy != MintedByTier || llo.MaxLifetimeS != 300 || !llo.RequiresConfinementDigest || llo.Grantable ||
		strings.Join(llo.ScopeCeiling, ",") != "bridgeCert" {
		t.Fatalf("llo-run/1 = %+v", llo)
	}
	dep, _ := LookupCriteria("deploy/1")
	if dep.MintedBy != MintedByAuthority || dep.MaxLifetimeS != 900 || dep.RequiresConfinementDigest || dep.Grantable ||
		strings.Join(dep.ScopeCeiling, ",") != "bridgeCert" {
		t.Fatalf("deploy/1 = %+v", dep)
	}
}

// notme scripts/task-cert/lib.ts parseLegacyCutoff + resolveLegacyCutoff.
func TestParseLegacyCutoff(t *testing.T) {
	good := map[string]time.Time{
		"2026-12-01":                     time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		"2026-12-01T00:00:00Z":           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		"2026-12-01T12:30Z":              time.Date(2026, 12, 1, 12, 30, 0, 0, time.UTC),
		"2026-12-01T12:00:00.123456789Z": time.Date(2026, 12, 1, 12, 0, 0, 123_000_000, time.UTC),
		"2026-12-01T12:00+23:59":         time.Date(2026, 11, 30, 12, 1, 0, 0, time.UTC),
		"2026-12-01T12:00-05:00":         time.Date(2026, 12, 1, 17, 0, 0, 0, time.UTC),
		"2026-12-31T24:00Z":              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		"2024-02-29T00:00Z":              time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC),
	}
	for raw, want := range good {
		got, err := ParseLegacyCutoff(raw)
		if err != nil || got == nil || !got.Equal(want) {
			t.Errorf("ParseLegacyCutoff(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	if got, err := ParseLegacyCutoff(""); err != nil || got != nil {
		t.Errorf("empty = %v, %v; want no cutoff", got, err)
	}
	for _, bad := range []string{
		"tomorrow", "2026-12", "2026-12-01T12:00", "2026-12-01 12:00Z", "2026-02-30", "2026-02-29", "2026-13-01",
		"2026-00-10", "2026-01-00", "2026-12-01T24:01Z", "2026-12-01T24:00:00.5Z", "2026-12-01T23:59:60Z",
		"2026-12-01T23:60Z", "2026-12-01T12:00+24:00", "2026-12-01T12:00+23:60", "1764547200",
	} {
		if got, err := ParseLegacyCutoff(bad); err == nil {
			t.Errorf("ParseLegacyCutoff(%q) = %v, want an error", bad, got)
		} else if !strings.Contains(err.Error(), "is not an ISO date") {
			t.Errorf("ParseLegacyCutoff(%q) error %q", bad, err)
		}
	}
}

func TestResolveLegacyCutoff(t *testing.T) {
	flag := func(s string) *string { return &s }
	if _, err := ResolveLegacyCutoff(flag(""), "2026-12-01"); err == nil || err.Error() != "--legacy-cutoff needs a value (an ISO date, e.g. 2026-12-01)" {
		t.Fatalf("empty flag: %v", err)
	}
	got, err := ResolveLegacyCutoff(flag("2027-01-01"), "2026-12-01")
	if err != nil || !got.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("flag wins: %v %v", got, err)
	}
	got, err = ResolveLegacyCutoff(nil, "2026-12-01")
	if err != nil || !got.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("env: %v %v", got, err)
	}
	if got, err := ResolveLegacyCutoff(nil, ""); err != nil || got != nil {
		t.Fatalf("empty env is unset: %v %v", got, err)
	}
	if _, err := ResolveLegacyCutoff(nil, "soon"); err == nil {
		t.Fatal("bad env accepted")
	}
}
