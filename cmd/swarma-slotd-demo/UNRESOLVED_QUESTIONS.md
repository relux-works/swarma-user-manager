# Deployment qualification still required

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
   outside the repository. No production installer, account adoption or recovery
   operation that fabricates a missing creation receipt is provided. An
   ambiguous partial create needs explicit reconciliation outside the wire API.

The service remains demo-only and carries only the v1 r4 protocol guarantees.

The expiry scanner still revalidates all records every 200 ms. It is bounded to
the protocol's slot range, but its performance at high slot counts is unmeasured;
a cache/scheduling change is a separate follow-up with recovery/coherency tests.
The protocol owner confirmed that r4 omits `slot` when no well-formed slot was
carried, and the station manager client agrees. The response section now states
that rule explicitly; no wire or client behavior changed.
