package qualification

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
)

// Public initial and boot issuance bind actual kernel CapEff. The private
// sampler exercises errors/retained authority/drift without changing host caps.
// Every refusal withdraws the old record and publishes no partial successor.
func TestD1IssuerCapabilities(t *testing.T) {
	for _, boot := range []bool{false, true} {
		for _, mode := range []string{"valid", "net-admin", "missing", "read-error", "drift"} {
			t.Run(mode+map[bool]string{false: "/initial", true: "/boot"}[boot], func(t *testing.T) {
				s, p, _, m, _ := setup()
				if boot {
					q, e := s.Issue(context.Background(), p, false)
					if e != nil {
						t.Fatal(e)
					}
					p.Qualified = true
					p.QualificationDigest = q.InputsDigest
				}
				m.b = []byte("old record")
				before := m.publishes
				calls := 0
				read := func() (string, error) {
					calls++
					switch mode {
					case "net-admin":
						return "0000000000001000", nil
					case "missing":
						return "", nil
					case "read-error":
						return "", ErrRequired
					case "drift":
						if calls > 1 {
							return "0000000000000001", nil
						}
					}
					return "0000000000000000", nil
				}
				ctx, diagnostic := WithDiagnostics(context.Background())
				q, e := s.issue(ctx, p, boot, read)
				if mode == "valid" {
					if e != nil || q.EffectiveCapabilities != "0000000000000000" || q.Format != RecordFormat || calls != 2 {
						t.Fatal("valid capability control", q, e, calls)
					}
				} else if e != ErrRequired || m.b != nil || m.publishes != before {
					t.Fatalf("capability refusal lost withdrawal: %v publishes=%d record=%s", e, m.publishes, m.b)
				}
				if mode != "valid" {
					stage := "issuer"
					if mode == "drift" {
						stage = "recapture"
					}
					want := "qualification_refused stage=" + stage + " check=effective_capabilities"
					if diagnostic.Line() != want {
						t.Fatalf("wrong capability refusal: %s", diagnostic.Line())
					}
				}

			})
		}
	}
	s, p, _, _, _ := setup()
	q, e := s.Issue(context.Background(), p, false)
	actual, err := linuxos.EffectiveCapabilities()
	if e != nil || err != nil || q.EffectiveCapabilities != actual {
		t.Fatal("public issuer did not bind kernel sample", e, err)
	}
}

// Version 3 requires canonical capability evidence without NET_ADMIN. Versions
// 1/2 are unsupported and never inferred/upgraded. A prepared reader also
// refuses any later capability-field change, even to another reduced mask.
func TestD1QualificationCapabilityField(t *testing.T) {
	for _, mode := range []string{"valid", "valid-other-capability", "missing", "null", "net-admin", "upper", "short", "bad-hex", "old-v1", "old-v2", "unknown-version"} {
		t.Run(mode, func(t *testing.T) {
			s, p, _, m, _ := issued(t)
			_ = s
			var v map[string]any
			if e := json.Unmarshal(m.b, &v); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "valid-other-capability":
				v["effective_capabilities"] = "0000000000000001"
			case "missing":
				delete(v, "effective_capabilities")
			case "null":
				v["effective_capabilities"] = nil
			case "net-admin":
				v["effective_capabilities"] = "0000000000001000"
			case "upper":
				v["effective_capabilities"] = "000000000000000A"
			case "short":
				v["effective_capabilities"] = "0"
			case "bad-hex":
				v["effective_capabilities"] = "000000000000000g"
			case "old-v1":
				v["format"] = "station-qualification/1"
			case "old-v2":
				v["format"] = "station-qualification/2"
			case "unknown-version":
				v["format"] = "station-qualification/4"
			}
			raw, e := Canonical(v)
			if e != nil {
				t.Fatal(e)
			}
			_, e = Decode(raw, p)
			if mode == "valid" || mode == "valid-other-capability" {
				if e != nil {
					t.Fatal("valid control", e)
				}
			} else if e != ErrRequired {
				t.Fatal("unsafe capability field accepted", mode, e)
			}
		})
	}
	s, p, _, m, _ := issued(t)
	g, e := s.Pin(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Release()
	q, e := Decode(m.b, p)
	if e != nil {
		t.Fatal(e)
	}
	q.EffectiveCapabilities = "0000000000000001"
	m.b, e = Canonical(q)
	if e != nil {
		t.Fatal(e)
	}
	if g.Check() != ErrRequired {
		t.Fatal("mismatched capability field accepted by prepared reader")
	}
	if !strings.Contains(string(m.b), "effective_capabilities") {
		t.Fatal("capability mismatch plant not applied")
	}
}
