package identities

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
)

const Format = "swarma-managed-identities/1"
const ServiceName = "credential-gateway"
const MaxBytes = 8 * 1024 * 1024

var ErrMismatch = errors.New("principal_ledger_mismatch")
var generationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Account struct {
	UID        uint32 `json:"uid"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Class      string `json:"class"`
	Placement  string `json:"placement"`
	Generation string `json:"generation"`
	State      string `json:"state"`
}

type Document struct {
	Format      string    `json:"format"`
	JournalHead string    `json:"journal_head"`
	Accounts    []Account `json:"accounts"`
}

func (document Document) Validate() error {
	if document.Format != Format || !hashPattern.MatchString(document.JournalHead) || document.Accounts == nil {
		return ErrMismatch
	}
	seenUIDs := map[uint32]bool{}
	services := map[string]bool{}
	for _, account := range document.Accounts {
		if account.UID == 0 || seenUIDs[account.UID] || !generationPattern.MatchString(account.Generation) || account.Generation == strings.Repeat("0", 32) || account.Name == "" || strings.ContainsRune(account.Name, 0) {
			return ErrMismatch
		}
		seenUIDs[account.UID] = true
		if account.Kind != "agent" && account.Kind != "service" && account.Kind != "workplace" {
			return ErrMismatch
		}
		if account.Class != "trusted" && account.Class != "untrusted" || account.Placement != "local" || account.State != "active" && account.State != "retired" {
			return ErrMismatch
		}
		if account.Kind == "service" {
			if account.Name != ServiceName || account.State == "active" && services[account.Name] {
				return ErrMismatch
			}
			if account.State == "active" {
				services[account.Name] = true
			}
		}
	}
	return nil
}

func Encode(document Document) ([]byte, error) {
	if document.Validate() != nil {
		return nil, ErrMismatch
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, ErrMismatch
	}
	value, err := ccj.Parse(raw, ccj.RegistrationMalformed)
	if err != nil {
		return nil, ErrMismatch
	}
	raw, err = ccj.Marshal(value, ccj.RegistrationMalformed)
	if err != nil || len(raw) > MaxBytes {
		return nil, ErrMismatch
	}
	return raw, nil
}

func Decode(raw []byte, journalHead string) (Document, error) {
	var document Document
	if len(raw) > MaxBytes {
		return document, ErrMismatch
	}
	value, err := ccj.Parse(raw, ccj.RegistrationMalformed)
	if err != nil {
		return document, ErrMismatch
	}
	canonical, err := ccj.Marshal(value, ccj.RegistrationMalformed)
	if err != nil || !bytes.Equal(canonical, raw) {
		return document, ErrMismatch
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.JournalHead != journalHead {
		return Document{}, ErrMismatch
	}
	reencoded, err := Encode(document)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return Document{}, ErrMismatch
	}
	return document, nil
}

func ValidateTransition(previous, next Document) error {
	if previous.Validate() != nil || next.Validate() != nil {
		return ErrMismatch
	}
	kinds := map[uint32]string{}
	for _, account := range previous.Accounts {
		kinds[account.UID] = account.Kind
	}
	for _, account := range next.Accounts {
		if kind, exists := kinds[account.UID]; exists && kind != account.Kind {
			return ErrMismatch
		}
	}
	return nil
}

func (document Document) Service(uid uint32, generation string) (Account, error) {
	if document.Validate() != nil {
		return Account{}, ErrMismatch
	}
	for _, account := range document.Accounts {
		if account.UID == uid && account.Generation == generation && account.Kind == "service" && account.State == "active" && account.Class == "trusted" && account.Placement == "local" {
			return account, nil
		}
	}
	return Account{}, ErrMismatch
}
