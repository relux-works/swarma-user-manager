//go:build linux

package slotd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

func ownedNFTRules(p policy, slot, token string) ([]byte, error) {
	if len(token) != 32 || !tokenPattern.MatchString(token) {
		return nil, errors.New("invalid nft receipt token")
	}
	b, e := nftRuleset(p, slot)
	if e != nil {
		return nil, e
	}
	return []byte(strings.Replace(string(b), "{\n", "{\n comment \"slotd-demo:"+token+"\"\n", 1)), nil
}

// The creation command itself must carry table userdata. Adding a declaration
// after an empty exclusive create does not update the kernel's table comment.
func exclusiveNFTRules(p policy, slot, token string) ([]byte, error) {
	rules, e := ownedNFTRules(p, slot, token)
	if e != nil {
		return nil, e
	}
	return append([]byte("create "), rules...), nil
}
func normalizeNFT(b []byte) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(string(b), ";", " ")), " ")
}
func tablePresence(b []byte, wanted string) (bool, error) {
	fields, ok := objectFields(b, "nftables")
	if !ok || len(fields) != 1 {
		return false, errors.New("invalid table inventory")
	}
	var entries []json.RawMessage
	if e := json.Unmarshal(fields["nftables"], &entries); e != nil {
		return false, e
	}
	if entries == nil {
		return false, errors.New("invalid table inventory")
	}
	found := false
	for _, entryBytes := range entries {
		entry, ok := objectFields(entryBytes, "metainfo", "table")
		if !ok || len(entry) != 1 {
			return false, errors.New("invalid table inventory entry")
		}
		if _, ok := entry["metainfo"]; ok {
			continue
		}
		raw := entry["table"]
		tableFields, ok := objectFields(raw, "family", "name", "handle", "flags", "comment")
		var family, name string
		if !ok || !stringField(tableFields, "family", &family) || !stringField(tableFields, "name", &name) || family == "" || name == "" {
			return false, errors.New("invalid table identity")
		}
		if family == "inet" && name == wanted {
			if found {
				return false, errors.New("duplicate table")
			}
			found = true
		}
	}
	return found, nil
}
func nftPresent(ctx context.Context, id slotIdentity) (bool, error) {
	b, e := runFixedTool(ctx, toolInvocation{Path: nftPath, Args: []string{"--json", "list", "tables"}})
	if e != nil {
		return false, e
	}
	return tablePresence(b, id.Table)
}
func verifyNFT(ctx context.Context, p policy, r *durableRecord) error {
	p.Egress = r.NFTPolicy
	expected, e := ownedNFTRules(p, r.Slot, r.NFTToken)
	if e != nil {
		return e
	}
	b, e := runFixedTool(ctx, toolInvocation{Path: nftPath, Args: []string{"--stateless", "--numeric", "--numeric-priority", "list", "table", "inet", r.Identity.Table}})
	if e != nil {
		return e
	}
	if normalizeNFT(b) != normalizeNFT(expected) {
		return errors.New("nft ownership or rules mismatch")
	}
	return nil
}
func installNFT(ctx context.Context, p policy, r *durableRecord, persist func() error) error {
	exists, e := nftPresent(ctx, r.Identity)
	if e != nil {
		return e
	}
	if exists {
		return verifyNFT(ctx, p, r)
	}
	r.NFTToken, e = randomToken()
	if e != nil {
		return e
	}
	r.NFTPolicy = append([]egressRule{}, p.Egress...)
	r.Phase = "nft-install"
	if e = persist(); e != nil {
		return e
	}
	rules, e := exclusiveNFTRules(p, r.Slot, r.NFTToken)
	if e != nil {
		return e
	}
	// A single exclusive declaration carries ownership and population in one
	// transaction. An existing table is never adopted, merged into or flushed.
	if _, e = runFixedTool(ctx, toolInvocation{Path: nftPath, Args: []string{"--file", "-"}, Stdin: rules}); e != nil {
		return e
	}
	if e = verifyNFT(ctx, p, r); e != nil {
		return e
	}
	r.Phase = ""
	return persist()
}
func removeNFT(ctx context.Context, p policy, r *durableRecord) error {
	exists, e := nftPresent(ctx, r.Identity)
	if e != nil {
		return e
	}
	if !exists {
		return nil
	}
	if e = verifyNFT(ctx, p, r); e != nil {
		return e
	}
	invocation, e := deleteNFTInvocation(p, r.Slot)
	if e != nil {
		return e
	}
	if _, e = runFixedTool(ctx, invocation); e != nil {
		return e
	}
	exists, e = nftPresent(ctx, r.Identity)
	if e != nil {
		return e
	}
	if exists {
		return errors.New("nft absence unproved")
	}
	return nil
}
