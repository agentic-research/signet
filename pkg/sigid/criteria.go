package sigid

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// notme's criteria extension (.1.10): which unit of identity a certificate
// is (signet-be49b9).
//
// A certificate carries SEQUENCE OF SEQUENCE { UTF8String name, INTEGER
// version }. A tier (Issuing CA) carries the criteria its approver granted,
// possibly several; a task carries exactly one, and it must be one its tier
// carries (task ⊆ tier, the same rule as scopes). The registry says what each
// criteria allows: who mints it, how long it may live, which scopes it may
// carry, and what else it requires. The extension is non-critical, like
// every notme extension: enforcement lives in verifiers, and this is one.
//
// THIS IS A PORT. The reference is notme worker/src/criteria.ts
// (checkCriteria) and scripts/task-cert/lib.ts (verifyChain,
// parseLegacyCutoff, resolveLegacyCutoff). The rules run in notme's order
// and every refusal reason is notme's string byte for byte, so `signet
// verify` and notme's `task-cert verify` refuse the same certificate for the
// same reason. cmd/signet/testdata/criteria holds certificates minted by
// notme's own code with notme's own verdicts; keep them passing.
var (
	// OIDCriteria is notme's .1.10 criteria extension.
	OIDCriteria = []int{1, 3, 6, 1, 4, 1, 99999, 1, 10}

	// OIDNotmeScopes is .1.3 under the NOTME profile: SEQUENCE OF
	// UTF8String scopes. signet's own certs use .1.3 for capabilities
	// (pkg/attest/x509 OIDSignetCapabilities); read it this way only on a
	// certificate the criteria rules are judging.
	OIDNotmeScopes = []int{1, 3, 6, 1, 4, 1, 99999, 1, 3}

	// OIDConfinementDigest is .1.7, ley-line-open's confinementDigest.
	// llo-run/1 requires its presence; its contents are not read here.
	OIDConfinementDigest = []int{1, 3, 6, 1, 4, 1, 99999, 1, 7}
)

// Criteria is one element of .1.10. Name carries no version suffix:
// agent-session/1 is Name "agent-session", Version 1.
type Criteria struct {
	Name    string
	Version int
}

// ID is "name/version".
func (c Criteria) ID() string { return c.Name + "/" + strconv.Itoa(c.Version) }

// MintedBy says who may issue a criteria's certificates.
type MintedBy string

const (
	// MintedByTier criteria are issued by a tier (Issuing CA), never the root.
	MintedByTier MintedBy = "tier"
	// MintedByAuthority criteria are issued by the authority's root directly.
	MintedByAuthority MintedBy = "authority"
)

// CriteriaDefinition is one entry of notme's registry.
type CriteriaDefinition struct {
	ID                        string
	MintedBy                  MintedBy
	MaxLifetimeS              int64
	ScopeCeiling              []string
	RequiresConfinementDigest bool
	Grantable                 bool // offered at notme's /enroll today
}

// certEligibleScopes mirrors notme worker/src/auth/passkey-cert-scopes.ts
// CERT_ELIGIBLE_SCOPES, in its order.
var certEligibleScopes = []string{"bridgeCert", "sign:git", "sign:attestation"}

var bridgeOnly = []string{"bridgeCert"}

// The three shipped criteria (notme mint-path design §6).
var criteriaRegistry = map[string]CriteriaDefinition{
	"agent-session/1": {
		ID: "agent-session/1", MintedBy: MintedByTier, MaxLifetimeS: 300,
		ScopeCeiling: certEligibleScopes, Grantable: true,
	},
	"llo-run/1": {
		ID: "llo-run/1", MintedBy: MintedByTier, MaxLifetimeS: 300,
		ScopeCeiling: bridgeOnly, RequiresConfinementDigest: true,
	},
	"deploy/1": {
		ID: "deploy/1", MintedBy: MintedByAuthority, MaxLifetimeS: 900,
		ScopeCeiling: bridgeOnly,
	},
}

// CriteriaIDs lists the registry's ids, sorted.
func CriteriaIDs() []string {
	ids := make([]string, 0, len(criteriaRegistry))
	for id := range criteriaRegistry {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// LookupCriteria returns the registry entry for "name/version".
func LookupCriteria(id string) (CriteriaDefinition, bool) {
	d, ok := criteriaRegistry[id]
	if ok {
		d.ScopeCeiling = slices.Clone(d.ScopeCeiling)
	}
	return d, ok
}

const maxCriteriaVersion = 0x7fffffff // a positive INTEGER of at most 4 DER bytes

var criteriaIDRe = regexp.MustCompile(`^([^/]+)/([1-9][0-9]*)$`)

// ParseCriteriaID parses "name/version" (notme parseCriteriaId).
func ParseCriteriaID(id string) (Criteria, bool) {
	m := criteriaIDRe.FindStringSubmatch(id)
	if m == nil {
		return Criteria{}, false
	}
	v, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil || v > maxCriteriaVersion {
		return Criteria{}, false
	}
	return Criteria{Name: m[1], Version: int(v)}, true
}

func validCriteriaShape(c Criteria) bool {
	return c.Name != "" && !strings.Contains(c.Name, "/") && c.Version >= 1 && c.Version <= maxCriteriaVersion
}

// EncodeCriteria is notme's encodeCriteria: DER SEQUENCE OF SEQUENCE {
// UTF8String, INTEGER }. An empty list, a bad shape or a duplicate is an
// error.
func EncodeCriteria(list []Criteria) ([]byte, error) {
	if len(list) == 0 {
		return nil, errors.New("criteria list must not be empty")
	}
	type elem struct {
		Name    string `asn1:"utf8"`
		Version int
	}
	seen := map[string]bool{}
	out := make([]elem, 0, len(list))
	for _, c := range list {
		if !validCriteriaShape(c) {
			return nil, fmt.Errorf("invalid criteria %+v", c)
		}
		if seen[c.ID()] {
			return nil, fmt.Errorf("duplicate criteria %s", c.ID())
		}
		seen[c.ID()] = true
		out = append(out, elem(c))
	}
	return asn1.Marshal(out)
}

type derTLV struct {
	tag        byte
	start, end int // content start; content end (== next TLV start)
}

// readTLV is notme's readTlv: one definite-length TLV at `at`, bounded by
// limit. Long-form lengths of 1..maxLenBytes bytes are accepted, minimal or
// not, as notme accepts them; an indefinite length is refused.
func readTLV(der []byte, at, limit, maxLenBytes int) (derTLV, bool) {
	if at+2 > limit {
		return derTLV{}, false
	}
	tag := der[at]
	n := int(der[at+1])
	start := at + 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > maxLenBytes || start+k > limit {
			return derTLV{}, false
		}
		n = 0
		for i := 0; i < k; i++ {
			n = n<<8 | int(der[start+i])
		}
		start += k
	}
	end := start + n
	if end > limit {
		return derTLV{}, false
	}
	return derTLV{tag: tag, start: start, end: end}, true
}

// decodeCriteriaList is notme criteria.ts decodeList.
func decodeCriteriaList(der []byte) ([]Criteria, bool) {
	outer, ok := readTLV(der, 0, len(der), 4)
	if !ok || outer.tag != 0x30 || outer.end != len(der) {
		return nil, false
	}
	var list []Criteria
	seen := map[string]bool{}
	for at := outer.start; at < outer.end; {
		el, ok := readTLV(der, at, outer.end, 4)
		if !ok || el.tag != 0x30 {
			return nil, false
		}
		name, ok := readTLV(der, el.start, el.end, 4)
		if !ok || name.tag != 0x0c {
			return nil, false
		}
		ver, ok := readTLV(der, name.end, el.end, 4)
		if !ok || ver.tag != 0x02 || ver.end != el.end {
			return nil, false
		}
		nameBytes := der[name.start:name.end]
		if !utf8.Valid(nameBytes) {
			return nil, false
		}
		v := der[ver.start:ver.end]
		if len(v) < 1 || len(v) > 4 || v[0]&0x80 != 0 { // positive, at most 4 bytes
			return nil, false
		}
		if len(v) > 1 && v[0] == 0 && v[1]&0x80 == 0 { // minimal encoding
			return nil, false
		}
		version := 0
		for _, b := range v {
			version = version<<8 | int(b)
		}
		c := Criteria{Name: string(nameBytes), Version: version}
		if !validCriteriaShape(c) || seen[c.ID()] {
			return nil, false
		}
		seen[c.ID()] = true
		list = append(list, c)
		at = el.end
	}
	if len(list) == 0 {
		return nil, false
	}
	return list, true
}

func extensionValue(cert *x509.Certificate, oid []int) ([]byte, bool) {
	id := asn1.ObjectIdentifier(oid)
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(id) {
			return ext.Value, true
		}
	}
	return nil, false
}

// ReadCriteria reads .1.10. present reports whether the extension exists;
// ok is false when it exists but is malformed.
func ReadCriteria(cert *x509.Certificate) (list []Criteria, present, ok bool) {
	der, present := extensionValue(cert, OIDCriteria)
	if !present {
		return nil, false, true
	}
	list, ok = decodeCriteriaList(der)
	return list, true, ok
}

// readNotmeScopes is notme cert-authority.ts readScopes over a present .1.3:
// SEQUENCE OF UTF8String spanning the value exactly, one- or two-byte
// long-form lengths. Strings decode leniently, as TextDecoder does: invalid
// bytes become U+FFFD and then fail the ceiling.
func readNotmeScopes(der []byte) ([]string, bool) {
	s, ok := readTLV(der, 0, len(der), 2)
	if !ok || s.tag != 0x30 || s.end != len(der) {
		return nil, false
	}
	var out []string
	for at := s.start; at < s.end; {
		e, ok := readTLV(der, at, s.end, 2)
		if !ok || e.tag != 0x0c {
			return nil, false
		}
		out = append(out, strings.ToValidUTF8(string(der[e.start:e.end]), "�"))
		at = e.end
	}
	return out, true
}

// CriteriaOptions are the verifier's inputs besides the certificates.
type CriteriaOptions struct {
	// At is the verification time, consulted only for LegacyCutoff; zero
	// means now. Lifetime is read from the certificate, never the clock.
	At time.Time
	// LegacyCutoff, when set, refuses a legacy (pre-criteria) task checked
	// strictly after it.
	LegacyCutoff *time.Time
}

// CriteriaVerdict is checkCriteria's result. On OK, Criteria is the task's
// criteria, or nil with Legacy set for a task under a pre-criteria tier.
type CriteriaVerdict struct {
	OK       bool
	Criteria *Criteria
	Legacy   bool
	Reason   string
}

func refuseCriteria(reason string) CriteriaVerdict { return CriteriaVerdict{Reason: reason} }

// CheckCriteria is notme's checkCriteria: one verdict on a leaf and the tier
// that issued it (nil when the authority's root issued the leaf itself). The
// caller has already verified the chain; this judges only the criteria.
func CheckCriteria(tier, leaf *x509.Certificate, opts CriteriaOptions) CriteriaVerdict {
	var tList []Criteria
	tPresent, tOK := false, true
	if tier != nil {
		tList, tPresent, tOK = ReadCriteria(tier)
	}
	lList, lPresent, lOK := ReadCriteria(leaf)

	if tPresent && !tOK {
		return refuseCriteria("malformed criteria on tier")
	}
	if lPresent && !lOK {
		return refuseCriteria("malformed criteria on leaf")
	}
	if lPresent && len(lList) > 1 {
		return refuseCriteria("a task carries exactly one criteria")
	}

	if !tPresent && !lPresent {
		at := opts.At
		if at.IsZero() {
			at = time.Now()
		}
		if opts.LegacyCutoff != nil && at.After(*opts.LegacyCutoff) {
			return refuseCriteria("legacy certificate past the operator's cutoff")
		}
		return CriteriaVerdict{OK: true, Legacy: true}
	}
	if !tPresent && lPresent && tier != nil {
		return refuseCriteria("task claims criteria its tier does not carry")
	}
	if tPresent && !lPresent {
		return refuseCriteria("tier carries criteria; the task names none")
	}

	c := lList[0]
	id := c.ID()
	def, known := criteriaRegistry[id]
	if !known {
		return refuseCriteria("unknown criteria " + id)
	}
	if (def.MintedBy == MintedByTier && tier == nil) || (def.MintedBy == MintedByAuthority && tier != nil) {
		return refuseCriteria(fmt.Sprintf("%s is minted by the %s only", id, def.MintedBy))
	}
	if tPresent && !slices.ContainsFunc(tList, func(g Criteria) bool { return g.ID() == id }) {
		return refuseCriteria(fmt.Sprintf("task criteria %s is not granted by its tier", id))
	}
	// X.509 times are whole seconds, so notme's Math.round is exact here.
	spanS := int64(leaf.NotAfter.Sub(leaf.NotBefore) / time.Second)
	if spanS > def.MaxLifetimeS {
		return refuseCriteria(fmt.Sprintf("%s allows at most %ds, this certificate spans %ds", id, def.MaxLifetimeS, spanS))
	}
	// An absent .1.3 carries no scopes; a present one that does not parse is
	// refused, never read as zero scopes (which would pass the ceiling).
	var scopes []string
	if der, ok := extensionValue(leaf, OIDNotmeScopes); ok {
		if scopes, ok = readNotmeScopes(der); !ok {
			return refuseCriteria("malformed scopes on leaf")
		}
	}
	for _, s := range scopes {
		if !slices.Contains(def.ScopeCeiling, s) {
			return refuseCriteria(fmt.Sprintf("%s does not allow scope %s", id, s))
		}
	}
	if def.RequiresConfinementDigest {
		if _, ok := extensionValue(leaf, OIDConfinementDigest); !ok {
			return refuseCriteria(id + " requires the run's confinementDigest (.1.7)")
		}
	}
	return CriteriaVerdict{OK: true, Criteria: &c}
}

var legacyCutoffRe = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})(T(\d{2}):(\d{2})(:(\d{2})(\.(\d+))?)?(Z|([+-])(\d{2}):(\d{2})))?$`)

// ParseLegacyCutoff is notme's parseLegacyCutoff: "" is no cutoff (nil), and
// anything but an ISO date is an error, never silently "no cutoff". It
// accepts what notme accepts: a calendar date (UTC midnight), or a date with
// HH:MM[:SS[.frac]] and a zone (Z or ±HH:MM). 24:00 is the next midnight, as
// in ECMAScript, and fractions are truncated to milliseconds.
func ParseLegacyCutoff(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	bad := fmt.Errorf("legacy cutoff %s is not an ISO date (e.g. 2026-12-01 or 2026-12-01T00:00:00Z)", strconv.Quote(raw))
	m := legacyCutoffRe.FindStringSubmatch(raw)
	if m == nil {
		return nil, bad
	}
	num := func(s string) int { n, _ := strconv.Atoi(s); return n }
	y, mo, d := num(m[1]), num(m[2]), num(m[3])
	day := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.UTC)
	// The calendar date must exist: 2026-02-30 does not roll into March.
	if mo < 1 || mo > 12 || day.Year() != y || int(day.Month()) != mo || day.Day() != d {
		return nil, bad
	}
	if m[4] == "" {
		return &day, nil
	}
	hh, mm, ss := num(m[5]), num(m[6]), num(m[8])
	ms := 0
	if frac := m[10]; frac != "" {
		ms = num((frac + "00")[:3])
	}
	switch {
	case hh == 24 && mm == 0 && ss == 0 && strings.Trim(m[10], "0") == "":
		// ECMAScript's end-of-day midnight.
	case hh > 23 || mm > 59 || ss > 59:
		return nil, bad
	}
	off := 0
	if m[11] != "Z" {
		zh, zm := num(m[13]), num(m[14])
		if zh > 23 || zm > 59 {
			return nil, bad
		}
		off = zh*3600 + zm*60
		if m[12] == "-" {
			off = -off
		}
	}
	t := day.Add(time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute +
		time.Duration(ss)*time.Second + time.Duration(ms)*time.Millisecond -
		time.Duration(off)*time.Second)
	return &t, nil
}

// ResolveLegacyCutoff is notme's resolveLegacyCutoff. flag is nil when
// --legacy-cutoff was not given; given with no value it is an error, since a
// flag the operator typed must never silently turn the cutoff off. The flag
// wins over env (NOTME_LEGACY_CUTOFF), where empty means unset.
func ResolveLegacyCutoff(flag *string, env string) (*time.Time, error) {
	if flag != nil {
		if *flag == "" {
			return nil, errors.New("--legacy-cutoff needs a value (an ISO date, e.g. 2026-12-01)")
		}
		return ParseLegacyCutoff(*flag)
	}
	return ParseLegacyCutoff(env)
}
