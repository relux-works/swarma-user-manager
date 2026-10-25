package pc2state

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type rule func(any) error

func fields(spec map[string]rule) rule {
	return func(v any) error {
		o, ok := v.(map[string]any)
		if !ok || len(o) != len(spec) {
			return ErrInvalid
		}
		for k, check := range spec {
			v, ok := o[k]
			if !ok {
				return ErrInvalid
			}
			if err := check(v); err != nil {
				return err
			}
		}
		return nil
	}
}

func number(low, high int64) rule {
	return func(v any) error {
		n, ok := v.(int64)
		if !ok || n < low || n > high {
			return ErrInvalid
		}
		return nil
	}
}

func oneOf(values ...string) rule {
	return func(v any) error {
		s, ok := v.(string)
		if ok {
			for _, value := range values {
				if s == value {
					return nil
				}
			}
		}
		return ErrInvalid
	}
}

func nullable(check rule) rule {
	return func(v any) error {
		if v == nil {
			return nil
		}
		return check(v)
	}
}

func array(check rule, maximum int) rule {
	return func(v any) error {
		a, ok := v.([]any)
		if !ok || a == nil || len(a) > maximum {
			return ErrInvalid
		}
		for _, v := range a {
			if err := check(v); err != nil {
				return err
			}
		}
		return nil
	}
}

func text(v any) error {
	s, ok := v.(string)
	if !ok || len(s) == 0 || len(s) > 255 || !utf8.ValidString(s) {
		return ErrInvalid
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return ErrInvalid
		}
	}
	return nil
}

func hexString(prefix string, digits int) rule {
	return func(v any) error {
		s, ok := v.(string)
		if !ok || len(s) != len(prefix)+digits || !strings.HasPrefix(s, prefix) {
			return ErrInvalid
		}
		for _, c := range s[len(prefix):] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return ErrInvalid
			}
		}
		return nil
	}
}

var (
	positive = number(1, SafeInteger)
	zero     = number(0, SafeInteger)
	uid      = number(0, 4294967295)
	d        = hexString("sha256:", 64)
	h        = hexString("", 64)
	id       = hexString("", 32)
)

func token(v any) error {
	if err := id(v); err != nil {
		return err
	}
	if v == strings.Repeat("0", 32) {
		return ErrInvalid
	}
	return nil
}

func boot(v any) error {
	s, ok := v.(string)
	if !ok || len(s) != 36 {
		return ErrInvalid
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return ErrInvalid
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrInvalid
		}
	}
	return nil
}

func checkpoint(v any) error {
	if err := fields(map[string]rule{"seq": zero, "hash": h})(v); err != nil {
		return err
	}
	o := v.(map[string]any)
	if o["seq"] == int64(0) && o["hash"] != strings.Repeat("0", 64) {
		return ErrInvalid
	}
	return nil
}

func meta(codec Kind, cap int64) rule {
	return fields(map[string]rule{"codec": oneOf(string(codec)), "digest": d, "bytes": number(1, cap)})
}

func attemptRule(preimage bool) rule {
	f := map[string]rule{
		"version": oneOf(string(ActivationAttempt)), "manager_id": id, "effect_digest": d,
		"target": fields(map[string]rule{"uid": uid, "generation": token, "registration_number": positive, "master_epoch": text, "predecessor_generation": token}),
		"owner":  text, "provision_effect": fields(map[string]rule{"caller_uid": uid, "caller_generation": token, "request_id": id}), "ordinal": positive,
		"source":        fields(map[string]rule{"transaction_revision": positive, "root_digest": d, "authority_incarnation": token, "withdrawal_counter": positive}),
		"prepared_tail": checkpoint, "active_record_hash": h, "boot_id": boot, "instance_id": id,
	}
	if !preimage {
		f["attempt_id"] = d
		f["disposition"] = oneOf("pending", "absent", "durable")
		f["evidence_digest"] = nullable(d)
	}
	return func(v any) error {
		if err := fields(f)(v); err != nil {
			return err
		}
		o := v.(map[string]any)
		if o["prepared_tail"].(map[string]any)["seq"] == int64(0) {
			return ErrInvalid
		}
		if !preimage && (o["evidence_digest"] == nil) != (o["disposition"] == "pending") {
			return ErrInvalid
		}
		return nil
	}
}

func recoveryRule(v any) error {
	if err := fields(map[string]rule{
		"version": oneOf(string(RecoveryRecord)), "recovery_id": id, "previous_digest": nullable(d), "phase": oneOf("open", "resolved", "release-prepared", "released"),
		"holds": array(d, 1), "root_digest": d, "journal": checkpoint, "outcome": oneOf("unknown", "absent", "durable"), "evidence_digest": nullable(d),
	})(v); err != nil {
		return err
	}
	o := v.(map[string]any)
	if len(o["holds"].([]any)) != 1 || (o["evidence_digest"] == nil) != (o["outcome"] == "unknown") || (o["phase"] == "open") != (o["outcome"] == "unknown") {
		return ErrInvalid
	}
	return nil
}

func guardRule(v any) error {
	if err := fields(map[string]rule{
		"version": oneOf(string(RecoveryGuard)), "revision": positive, "previous_digest": nullable(d), "inventory": meta(ManagerInventory, 65536),
		"phase":   oneOf("clear", "open", "resolved", "release-prepared", "released"),
		"holds":   array(fields(map[string]rule{"kind": oneOf("activation", "authority"), "origin_id": d, "hold_id": d}), 1),
		"attempt": nullable(meta(ActivationAttempt, 4096)), "resolution": nullable(meta(RecoveryRecord, 8192)),
		"release_prepared": nullable(meta(RecoveryRecord, 8192)), "released": nullable(meta(RecoveryRecord, 8192)), "source_root_digest": d,
	})(v); err != nil {
		return err
	}
	o := v.(map[string]any)
	rows := o["holds"].([]any)
	if o["phase"] == "clear" {
		if len(rows) != 0 || o["attempt"] != nil || o["resolution"] != nil || o["release_prepared"] != nil || o["released"] != nil {
			return ErrInvalid
		}
		return nil
	}
	if len(rows) != 1 || (o["attempt"] != nil) != (rows[0].(map[string]any)["kind"] == "activation") {
		return ErrInvalid
	}
	rank := map[string]int{"open": 0, "resolved": 1, "release-prepared": 2, "released": 3}[o["phase"].(string)]
	for i, k := range []string{"resolution", "release_prepared", "released"} {
		if (o[k] != nil) != (i < rank) {
			return ErrInvalid
		}
	}
	return nil
}
