// Package qualification implements the closed local-v0 qualification protocol.
// Its observations grant no account ownership, cleanup permission or cached absence.
package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

var ErrRequired = errors.New("qualification_required")

const RecordFormat = "station-qualification/3"

const ZeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

type StationRange struct {
	UIDMin int64 `json:"uid_min"`
	UIDMax int64 `json:"uid_max"`
	GIDMin int64 `json:"gid_min"`
	GIDMax int64 `json:"gid_max"`
}
type Inputs struct {
	Format           string                   `json:"format"`
	PolicyDigest     string                   `json:"policy_digest"`
	BinaryDigest     string                   `json:"binary_digest"`
	BackendDigest    string                   `json:"backend_digest"`
	SkeletonDigest   string                   `json:"skeleton_digest"`
	NSSConfiguration linuxos.NSSConfiguration `json:"nss_configuration"`
	NSSModules       []linuxos.NSSModule      `json:"nss_modules"`
	StationRange     StationRange             `json:"station_range"`
}
type Check struct {
	Result string `json:"result"`
	Reason string `json:"reason"`
}
type Checks struct {
	PolicyProtection    Check `json:"policy_protection"`
	SourceConfiguration Check `json:"source_configuration"`
	ApprovedSkeleton    Check `json:"approved_skeleton"`
	CronDenial          Check `json:"cron_denial"`
	AtDenial            Check `json:"at_denial"`
	AllowPrecedence     Check `json:"allow_precedence"`
	NoLinger            Check `json:"no_linger"`
	AccountDirectory    Check `json:"account_directory"`
	DynamicUserRanges   Check `json:"dynamic_user_ranges"`
	NoLauncher          Check `json:"no_launcher"`
	AccountRestrictions Check `json:"account_restrictions"`
}

func (c Checks) values() []Check {
	return []Check{c.PolicyProtection, c.SourceConfiguration, c.ApprovedSkeleton, c.CronDenial, c.AtDenial, c.AllowPrecedence, c.NoLinger, c.AccountDirectory, c.DynamicUserRanges, c.NoLauncher, c.AccountRestrictions}
}
func (c Checks) valid() bool {
	for _, v := range c.values() {
		switch v.Result {
		case "ok":
			if v.Reason != "" {
				return false
			}
		case "failed", "unknown":
			switch v.Reason {
			case "unsafe", "mismatch", "unavailable", "unsupported", "limit":
			default:
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (c Checks) Passing() bool {
	if !c.valid() {
		return false
	}
	for _, v := range c.values() {
		if v.Result != "ok" {
			return false
		}
	}
	return true
}

type Issuer struct {
	Mode         string `json:"mode"`
	InvocationID string `json:"invocation_id"`
}

func ValidInvocationID(s string) bool {
	return len(s) == 32 && s != strings.Repeat("0", 32) && validHash(s+s)
}

type Record struct {
	EffectiveCapabilities string   `json:"effective_capabilities"`
	Issuer                Issuer   `json:"issuer"`
	Format                string   `json:"format"`
	Inputs                Inputs   `json:"inputs"`
	InputsDigest          string   `json:"inputs_digest"`
	StationNames          []string `json:"station_names"`
	Checks                Checks   `json:"checks"`
	BootID                string   `json:"boot_id"`
	IssuedAtUnixMS        int64    `json:"issued_at_unix_ms"`
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return len(s) == 64 && e == nil && hex.EncodeToString(b) == s
}
func Canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrRequired
	}
	x, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return nil, ErrRequired
	}
	return ccj.Marshal(x, ccj.RegistrationMalformed)
}
func decode(b []byte, out any) error {
	x, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return ErrRequired
	}
	c, e := ccj.Marshal(x, ccj.RegistrationMalformed)
	if e != nil || !bytes.Equal(c, b) {
		return ErrRequired
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrRequired
	}
	c, e = Canonical(out)
	if e != nil || !bytes.Equal(c, b) {
		return ErrRequired
	}
	return nil
}
func PolicyDigest(p manager.Policy) (string, error) {
	if manager.ValidatePolicy(p) != nil {
		return "", ErrRequired
	}
	p.Qualified = false
	p.QualificationDigest = ZeroDigest
	b, e := Canonical(struct {
		Domain string         `json:"domain"`
		Policy manager.Policy `json:"policy"`
	}{"station-qualification-policy/1", p})
	if e != nil {
		return "", e
	}
	return Hash(b), nil
}
func (i Inputs) Digest() (string, error) {
	b, e := Canonical(i)
	if e != nil {
		return "", e
	}
	return Hash(b), nil
}
func (i Inputs) Validate(p manager.Policy) error {
	pd, e := PolicyDigest(p)
	r := i.StationRange
	if e != nil || i.Format != "station-qualification-inputs/1" || i.PolicyDigest != pd || !validHash(i.BinaryDigest) || i.BackendDigest != p.BackendDigest || i.SkeletonDigest != p.SkeletonDigest || r != (StationRange{p.UIDMin, p.UIDMax, p.GIDMin, p.GIDMax}) {
		return ErrRequired
	}
	// Recorded physical NSS lines are preserved exactly; unsupported actions remain unknown.
	names, e := linuxos.RecordedNSSConfiguration(i.NSSConfiguration, int(p.Limits.DeleteEntries))
	if e != nil {
		return ErrRequired
	}
	for _, module := range i.NSSModules {
		if int64(len(module.UIDRanges)) > p.Limits.DeleteEntries || int64(len(module.GIDRanges)) > p.Limits.DeleteEntries {
			return ErrRequired
		}
	}
	if linuxos.ValidateNSSModules(names, i.NSSModules, linuxos.IDInterval{Min: uint32(r.UIDMin), Max: uint32(r.UIDMax)}, linuxos.IDInterval{Min: uint32(r.GIDMin), Max: uint32(r.GIDMax)}) != nil {
		return ErrRequired
	}
	if int64(len(i.NSSModules)) > p.Limits.DeleteEntries {
		return ErrRequired
	}
	return nil
}

var stationName = regexp.MustCompile(`^worker-[a-z0-9][a-z0-9-]{0,22}$`)
var bootID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validNames(names []string, p manager.Policy) bool {
	if names == nil || int64(len(names)) > p.Limits.DeleteEntries {
		return false
	}
	for j, n := range names {
		if !stationName.MatchString(n) || j > 0 && strings.Compare(names[j-1], n) >= 0 {
			return false
		}
	}
	return true
}

// The version-3 field is exactly the 64-bit kernel CapEff mask, lowercase hex.
// A retained CAP_NET_ADMIN or absent/malformed evidence cannot qualify D1.
func validEffectiveCapabilities(s string) bool {
	if len(s) != 16 || strings.ToLower(s) != s {
		return false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	return err == nil && strings.IndexFunc(s, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) < 0 && v&(1<<12) == 0
}

func (q Record) Validate(p manager.Policy) error {
	if q.Issuer.Mode == "initial" {
		if q.Issuer.InvocationID != "" {
			return ErrRequired
		}
	} else if q.Issuer.Mode != "boot" || !ValidInvocationID(q.Issuer.InvocationID) {
		return ErrRequired
	}
	if q.Format != RecordFormat || !validEffectiveCapabilities(q.EffectiveCapabilities) || q.Inputs.Validate(p) != nil || !validNames(q.StationNames, p) || !q.Checks.valid() || !bootID.MatchString(q.BootID) || q.IssuedAtUnixMS <= 0 {
		return ErrRequired
	}
	h, e := q.Inputs.Digest()
	if e != nil || h != q.InputsDigest {
		return ErrRequired
	}
	return nil
}
func Decode(b []byte, p manager.Policy) (Record, error) {
	var q Record
	if len(b) == 0 || int64(len(b)) > p.Limits.RecordBytes || decode(b, &q) != nil || q.Validate(p) != nil {
		return Record{}, ErrRequired
	}
	return q, nil
}

// DecodeClosed authenticates canonical closed deployment configuration records.
// Required fields are enforced by exact typed re-encoding, including zero values.
func DecodeClosed(b []byte, out any, max int64) error {
	if len(b) == 0 || int64(len(b)) > max {
		return ErrRequired
	}
	return decode(b, out)
}
