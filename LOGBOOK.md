# Logbook

## 2026-10-11 — TASK-261011-1kho6b: R-UM1 contract alignment

Documentation now distinguishes root correlation from downstream effect IDs, writes the start receipt before dropping privileges, and routes stop through receipt/process identity checks in `exec.stop`. The launch diagram uses managed UID 30412. D-DONOR-PROVISIONING assigns donor provisioning to a separate component; variant B remains disabled until its specification exists. D-WIRE-NAMES prefixes request/result kinds with the repository name; the README reference follows the spec.

Contract P7 leaves the unified retirement fate set undecided, and the supplied owner decisions do not cover it. The spec retains archive/delete in the current request and explicitly asks whether to admit operator-only `keep` or remove it from policy. The earlier keep policy is marked inactive pending that choice. W3 signed-request grammar and I4 SH2 ticket/host-role activation also remain explicit owner questions. No protocol bytes or donor component name were invented. D-IDENTITY separates account retirement from one-shot/standing identity revocation; D-EXECUTOR and D-PATH constrain the caller-composed execution plan.

This is a docs-only change. Tests, builds and diagram rendering are not run on this host under the task brief; document inspection and whitespace validation are recorded in the task-scoped alignment outcome. No runtime qualification is claimed.
