# Deployment qualification still required

The [DK5b typed profile](STATION-PAYLOAD.md) remains an implementation draft.
Public bootstrap/model and staged-config adapters use the published chain-lab
API with no local replace: `single-use` `v0.3.1-0.20261112085009-7ea1800ed187`
(chain-lab main `7ea1800`, the corrected public module graph), which selects
`sealwatch` `v0.2.1-0.20261111181054-288d63e191fe` with `ValidateJSON`. The
earlier `288d63e1` pin selected `sealwatch v0.1.0` and failed to compile for an
external consumer; that blocker is resolved. Portable tests run on Linux/amd64
without root; root fixtures run only on the hosted runner. No typed Create/start qualification,
deployment or automatic migration is claimed. Require real two-UID sandbox/custody and pre-exec refusal controls,
interrupted Create/Destroy evidence, retained journal identity, exact composed
payload consumer and independent review before activation. The separate install
package draft must explicitly provision the new protected shared parents and
approved per-UID staging; it is not assumed landed or already installed.

The demo-local filesystem and receipt-backed restart-retirement contract is
implemented without changing `internal/linuxos`. Its previous API integration
gaps no longer block this implementation.

The approved prestart fence is implemented but needs exact-head hosted evidence
and accepted delta review before activation. It verifies actual limits, complete
policy-bound BPF programs/maps and NFT before the unchanged payload ExecStart;
configuration-property readback alone is not enforcement evidence. Guarded
missing/incorrect enforcement controls require a payload execution sentinel to
remain absent. No deployment qualification follows from compile or vet success.

1. Gather passing portable and guarded root workflow evidence for the exact
   reviewed head, including both effective egress layers. Authored tests,
   compile-only binaries and source inspection are not this evidence.
2. Independently review the implementation and qualify the intended disposable
   host's systemd, cgroup-v2/BPF, nftables, NSS and filesystem behavior. A runner
   result alone does not qualify a deployment.
3. The operator must provision the protected real policy, payload and home parent
   outside the repository. Demo adoption is limited to the declared account and
   its receipt gates; no production installer or recovery operation that
   fabricates a missing creation receipt is provided. An
   ambiguous partial create needs explicit reconciliation outside the wire API.

The service remains demo-only and carries only the v1 r4 protocol guarantees.

The expiry scanner still revalidates all records every 200 ms. It is bounded to
the protocol's slot range, but its performance at high slot counts is unmeasured;
a cache/scheduling change is a separate follow-up with recovery/coherency tests.
The protocol owner confirmed that r4 omits `slot` when no well-formed slot was
carried, and the station manager client agrees. The response section now states
that rule explicitly; no wire or client behavior changed.

## Slot egress scope (open)

The slot reaches IP destinations only through the root policy allowlist, in two
layers (systemd `IPAddressDeny=any` plus per-address allow, and the per-UID nft
table ending in a counted drop). The typed policy requires the profile gateway as
an exact TCP rule. Two parts of a "relay, wallet socket and model proxy only"
egress contract are not enforced here and need an owner decision:

1. The model proxy is reachable only if the operator lists it in `egress`. The
   per-booking bootstrap `model_endpoint` may be a hostname, so slotd does not
   derive or cross-check an egress rule from it.
2. T19 now confines pathname and abstract Unix sockets and address families;
   the implemented contract and reviewed hosted fixtures are in the
   [daemon README](README.md#slot-confinement-t19). Source delivery does not
   establish host adoption. The observational real-host harness still needs an
   actual operator maintenance-window run on rt-stations and the separate
   connection-only real-wallet observation on stations1. A stand-in result
   cannot substitute for stations1 wallet evidence. The hook-only experiments
   remain covered only by exact-tree hosted root CI. The producer cannot run
   these station modes without the installed daemon and explicit root marker.
