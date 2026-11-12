package slotd

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

var tokenPattern = regexp.MustCompile(`^[0-9a-f]+$`)

// A durable intent precedes each external effect. Receipts authorize only the
// objects they describe; an unfinished intent is not a creation receipt.
type durableRecord struct {
	Version       int             `json:"version"`
	Slot          string          `json:"slot"`
	Identity      slotIdentity    `json:"identity"`
	Binding       record          `json:"binding"`
	BootID        string          `json:"boot_id"`
	Phase         string          `json:"phase"`
	Accounts      *accountReceipt `json:"accounts"`
	Home          *fileStamp      `json:"home"`
	NFTToken      string          `json:"nft_token"`
	NFTPolicy     []egressRule    `json:"nft_policy"`
	UnitToken     string          `json:"unit_token"`
	Cgroup        string          `json:"cgroup"`
	UnitRuntimeUS int64           `json:"unit_runtime_us"`
	Station       *stationRecord  `json:"station,omitempty"`
}

type accountReceipt struct {
	PasswdSHA256  string `json:"passwd_sha256"`
	GroupSHA256   string `json:"group_sha256"`
	ShadowPresent bool   `json:"shadow_present"`
}

type fileStamp struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func encodeDurable(r durableRecord) ([]byte, error) {
	b, err := json.Marshal(r)
	return append(b, '\n'), err
}

// State is protected configuration, never request input. Canonical encoding
// also refuses duplicate/unknown fields, extra records and ambiguous numbers.
func decodeDurable(b []byte, p policy, slot string) (durableRecord, error) {
	var r durableRecord
	if len(b) > 64*1024 {
		return r, errors.New("record too large")
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	canonical, err := encodeDurable(r)
	if err != nil || !bytes.Equal(b, canonical) {
		return r, errors.New("noncanonical record")
	}
	id, err := p.identity(slot)
	if err != nil || (r.Version != 1 && r.Version != 2) || r.Slot != slot || r.Identity != id || !bootPattern.MatchString(r.BootID) || !digestPattern.MatchString(r.Binding.PayloadSHA256) || !digestPattern.MatchString(r.Binding.BootstrapSHA256) || r.Binding.NotAfter.IsZero() || r.Binding.NotAfter.Nanosecond() != 0 || r.Binding.NotAfter.Location() != time.UTC {
		return r, errors.New("invalid record binding")
	}
	switch r.Binding.State {
	case created, running, stopped, destroyed, failed:
	default:
		return r, errors.New("invalid stored state")
	}
	switch r.Phase {
	case "", "account-create", "home-create", "bootstrap-create", "station-create", "station-remove", "nft-install", "unit-start", "unit-stop", "nft-remove", "account-remove", "home-remove":
	default:
		return r, errors.New("invalid effect intent")
	}
	if r.Accounts != nil && (!digestPattern.MatchString(r.Accounts.PasswdSHA256) || !digestPattern.MatchString(r.Accounts.GroupSHA256) || !r.Accounts.ShadowPresent) {
		return r, errors.New("invalid account receipt")
	}
	if r.Home != nil && r.Home.Inode == 0 {
		return r, errors.New("invalid home receipt")
	}
	for _, token := range []string{r.NFTToken, r.UnitToken} {
		if token != "" && (len(token) != 32 || !tokenPattern.MatchString(token)) {
			return r, errors.New("invalid resource token")
		}
	}
	if r.Cgroup != "" && r.Cgroup != "/system.slice/"+id.Unit {
		return r, errors.New("invalid cgroup")
	}
	if (r.UnitToken == "") != (r.Cgroup == "") || (r.UnitToken == "" && r.UnitRuntimeUS != 0) || (r.UnitToken != "" && r.UnitRuntimeUS <= 0) {
		return r, errors.New("invalid unit receipt")
	}
	if _, err := validateEgress(r.NFTPolicy); err != nil {
		return r, err
	}
	if err := validateStationRecord(&r, p); err != nil {
		return r, err
	}
	// A crash never turns an intent into a receipt or a repeatable successful op.
	if r.Phase != "" {
		r.Binding.State = failed
	}
	return r, nil
}
