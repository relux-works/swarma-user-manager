# Deployment qualification still required

The demo-local filesystem and receipt-backed restart-retirement contract is
implemented without changing `internal/linuxos`. Its previous API integration
gaps no longer block this implementation.

Activation is currently blocked: systemd's configured unit properties do not
prove that its best-effort BPF attachment and controller writes succeeded. The
current implementation starts the payload before reading those properties.
A passing supported-runner test cannot close a per-unit installation-failure
window. A mandatory launch fence must establish actual limits and the required
filter attachments before the payload executes, with guarded refusal tests and
a payload execution sentinel. The frozen `ExecStart=payload argv` and fixed-tool
contract needs an explicit fence-helper or launcher decision before that change.
Do not deploy this head while that review finding is unresolved.

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
