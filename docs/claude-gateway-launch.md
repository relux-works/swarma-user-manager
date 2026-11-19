# Protected Claude gateway launch mapping v1

Status: **owner decision 2026-11-19, Core review pending**. The decision binds
the launcher and gateway qualification units only; Core review is scheduled
for 2026-11-22. It does not activate, install or qualify a gateway, broker,
station deployment or operator interface.

## Sources and boundary

This implements the worker side of the dated owner decision, informed by the
bounded Claude Code 2.1.328 wire probe. The probe used no real credentials or
upstream model and does not establish production authentication or readiness.
The Swarma book chapter 8, *Agent launch and session host*
(`book/ru/08-zapusk-i-host-sessiy.md`), separates the privileged launcher from
plan construction and assigns only a placeholder to the secret-free worker.
[Helper §7](../spec/helper.md#7-the-launcher-swarma-user-launcher) retains
executable approval, descriptor scrubbing and root receipt ownership;
[the first-run selection](design/first-run-launch-stop.md) retains its start,
stop and qualification gates. These boundaries are unchanged. The following
wire/configuration refinement is the owner-decided qualification contract,
not a substitute for pending Core review or a broader book/spec publication.

The placeholder is not authority. Gateway peer admission, real credential
ownership, upstream injection and SSE forwarding belong to the gateway and
are outside this launcher change.

## Selection index

`<root>/etc/launch-mappings/index.json` is closed canonical CCJ-1:

```json
{"format":"station-launch-mappings/1","mapped":["approved-executor"]}
```

Only `format` and `mapped` exist. `mapped` is a non-null array of sorted,
unique executor IDs in the existing approved-executor grammar. The parent
directory is root:root 0755. The index and each mapping are root:root 0644,
regular, single-link files. Directory components and files must not be
symlinks; reads use no-follow descriptors and fstat metadata checks. Reads
are bounded by the launch request byte limit.

- An absent index (including an absent mappings directory) maps no executor.
- A valid index not listing the requested executor leaves its launch unchanged,
  even if a same-named mapping file is missing or invalid.
- A listed executor requires its mapping to exist and validate. An unsafe or
  invalid present selection index cannot be treated as absent or empty.
- The index and selected mapping are each read once per launch. There is no
  caller environment or launch-op override and no receipt extension.

## Per-executor mapping

`<root>/etc/launch-mappings/<executor_id>.json` has exactly these members.
The layout below is explanatory; installed bytes must be canonical CCJ-1.

```json
{
  "format": "station-launch-mapping/1",
  "executor_id": "approved-executor",
  "executor_sha256": "approved-executor-sha256",
  "kind": "claude-gateway",
  "gateway_socket": "<root>/run/credential-gateway/<generation>/gateway.sock",
  "base_url": "http://api.anthropic.com",
  "credential_variable": "CLAUDE_CODE_OAUTH_TOKEN",
  "placeholder": "ssh-placeholder",
  "network": "unix-only"
}
```

Every value is closed to the displayed literal except executor ID, approved
lowercase 64-hex SHA-256 and socket generation. The ID must be the selected
approved executor, and the digest must equal the approved digest already
verified against the retained executable. The socket path is exactly the
displayed root-relative layout, with no aliases, traversal or extra segments.
The gateway listener grammar from `swarma-chain-lab/docs/gateway-service.md`
requires an initial ASCII alphanumeric followed by at most 127 ASCII
alphanumerics, dots, underscores or hyphens. `.` and `..` refuse. The socket
and its directory components are checked without following links; the final
descriptor-relative lstat must identify a socket. No gateway credential is
read, copied or delivered by the launcher.

## Ordered worker launch

1. Verify the executable against the approved pin, as before.
2. Read and validate the selection index and, if listed, mapping in one read
   pass, including owner, group, exact mode, type and single-link fstat checks.
3. Check the mapped generation socket with no-follow directory traversal and
   descriptor-relative lstat. It must exist and be a socket.
4. Perform existing launch admission and receipt persistence. Receipt encoding
   is byte-identical; qualification evidence separately pins the mapping file
   SHA-256. A receipt still establishes only an attempted start.
5. Drop privileges using the existing verified account transition. Existing
   committed-start rechecks and durable accounting remain in their order.
6. Compose only the following final environment, without inheriting caller
   entries or taking values from launch-op input:

```text
HOME=<approved account home>
USER=<approved account username>
LOGNAME=<approved account username>
PATH=/usr/bin:/bin
LANG=C.UTF-8
TMPDIR=<approved account home>/tmp
ANTHROPIC_UNIX_SOCKET=<validated gateway_socket>
ANTHROPIC_BASE_URL=http://api.anthropic.com
CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
DISABLE_TELEMETRY=1
DISABLE_ERROR_REPORTING=1
DISABLE_AUTOUPDATER=1
DISABLE_UPDATES=1
```

`ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are never set. The existing
descriptor scrub remains. Traffic-disable flags do not establish confinement.

7. Before exec, set no-new-privileges and install the Unix-only seccomp filter.
   Native amd64 and arm64 are supported; other native ABIs refuse. Only AF_UNIX
   `socket` and `socketpair` creation is allowed. Every other family and all
   three io_uring setup/enter/register syscalls refuse with EPERM. The audit
   architecture gate rejects other ABIs, including compat socketcall; x32
   syscall numbers also refuse. TSYNC applies the filter to existing threads;
   it survives exec and descendants. Any load or thread-sync failure refuses
   before exec. No helper, firewall or namespace outside this process changes.
8. Exec the retained approved executable as before. Unlisted executors keep
   the original six-entry environment and do not acquire this filter.

## Refusals and durable evidence

| Code | Cause |
| --- | --- |
| `launch_mapping_unavailable` | A selected mapping cannot be read, or its socket is absent, linked, inaccessible or not a socket. |
| `launch_mapping_invalid` | Unsafe mapping/index metadata, links, size, noncanonical or duplicate JSON, unknown/missing members, unordered/duplicate IDs, wrong literals, ID, digest syntax or socket path. |
| `launch_mapping_digest_mismatch` | A well-formed mapping digest differs from the approved executor digest. |
| `launch_confinement_unavailable` | Missing confinement primitive, unsupported native ABI, no-new-privileges or seccomp/TSYNC failure. |

Existing executable refusal codes remain and precede mapping intake. Mapping
and socket refusals occur before admission, receipt, drop or committed start.
Confinement refusal occurs after the existing durable attempted-start receipt
and committed debit; those bytes remain as evidence and prevent a second
start. Existing stop obligations are not cleared by a refusal.

## Tests and evidence limits

`go test ./internal/launch -run '^TestLaunch(Mapping|Confinement)' -count=1 -v`
covers inherited/input environment rejection, absent selection, unsafe files
and directories, closed schemas, approved digest binding, socket grammar/type,
exact legacy output and unchanged receipt bytes. Real child processes compare
unfiltered internet/Unix controls with filtered refusal, exec inheritance,
descendant inheritance, TSYNC and a planted kernel filter-load denial. BPF
evaluation separately prevents host-level io_uring or socket restrictions from
masquerading as the filter's own enforcement. Narrowing source plants require
their named assertion to fail while a valid control remains green.

Ownership negatives use independent stat fixtures beside real fstat controls;
they do not claim root installation or native privilege-drop qualification.
Build, race, vet and fixture evidence do not establish an installed gateway,
cross-task peer authorization, real upstream credentials or Core acceptance.
