# Unresolved station-account questions

The [station-account v0 draft](spec/stations-v0.md) is a specification slice,
not a production capability. Architecture decisions and remaining publication
gates are distinguished below.
The broader [helper.md §14](spec/helper.md#14-open-questions) retains its own
later-phase questions; this register does not resolve or renumber them.

## Decided architecture

| Decision | Binding disposition |
|---|---|
| Q1 — same-account generation bump: decided | Same reserved account/UID; destructive home/temp reset, fresh random token and no key carry-over. Outside-home UID residue or unknown inventory refuses bump and routes to ordinary retirement plus a new account. Old removed, reviewed Keymaker pin re-admission, new binding, then new active is mandatory ([§6](spec/stations-v0.md#6-same-account-generation-bump)). |
| Architecture Q3 — journal/ledger authority: decided | The generation journal is authoritative. `ledger.json` is a derived view rebuilt from the verified journal on divergence; the journal wins ([helper.md §4.5](spec/helper.md#45-userlist-and-the-ledger)). |
| Station Q3 — effect encoding: specified for review | The [OS-effect receipt contract](spec/station-effect-receipts.md) selects a versioned closed store, write-ahead object identities, receipt-backed recovery/quarantine, unlocked backend I/O and exact reserved-identity restoration. This resolves the encoding specification slice, not review, implementation/migration, cleanup authority or root qualification. Unreceipted objects remain fenced; name/UID matches are not ownership. |
| Station v0 authority sources: selected | The [six local-v0 providers and shared interface](spec/station-effect-receipts.md#6-accepted-local-v0-authority-sources) select root policy qualification, operator-only per-act retirement/export waiver, approved skeleton, cron/at deny plus no linger, no-launcher process fence/full inventory and local locked activation guard. Root can bypass the process restriction; v0 retirement has no export confirmation. Implementation and qualification are still required. |
| Qualification issuer and account directory: specified for review | [Receipts §§6.3–6.5](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record) select root-only `qualify`, a stable policy/binary/backend/skeleton/range/NSS input pin with fresh protected boot-bound records and a networkless root boot oneshot, exact NSS lines, the files/systemd-only matrix with protected empty/absent userdb roots, exact Varlink closure and source-backed inclusive module ranges, authoritative protected local databases with full NSS agreement, and the existing fresh no-launcher inventory fence. This settles issuer/configuration selection; the files-only issuer/reader implementation still requires review and root/boot-unit qualification. |

The [A3 automatic update specification](spec/upgrade-requalification.md) selects
the sole bounded automatic re-pin exception: complete signed apt chain,
unchanged trust root, transaction attribution, no downgrade and full initial →
pin → boot-unit checks. It never opens admission or changes generations. P7
closes new starts immediately and requires verified narrowing or stop within a
published finite deadline. Owner/curator failure notification is mandatory;
transport remains a separate interface. A1p's administrator command is separate.

Architecture Q3 above is distinct from station publication gate Q3 below;
closing the authority decision does not close cleanup authority. The effect
encoding proposal is now published separately; remaining gates follow.

## Remaining station publication gates

| Question | Decision or missing contract | Safe state until resolved |
|---|---|---|
| Q2 — authoritative generation format | Align the reviewed generation journal format (spec/generation-journal.md), `gen-journal/1`, by revision and actual sections: append/flush/recovery, failed-create transitions, retained-account bump, reader projection, final-release lock/exclusion, restore fence and reader floors. Confirm Keymaker §§3.1–3.2's check/commit/release serialization and the station spec's §6.2 reviewed pre-active provisioning/confirmation adapter. Its current register requires an active target and cannot satisfy the decided binding-before-active order; no temporary activation is allowed. | No production writer/consumer qualification; no static-UID or cached-ledger authority. |
| Q3 — receipt implementation and cleanup admission | Review/implement the [published v2 effect encoding and crash reconciliation](spec/station-effect-receipts.md#2-versioned-effect-store-encoding), lock protocol and restoration contract. Qualify migration, finite bounds/capacity and protected maintenance reconciliation for unreceipted OS writes. Publish concrete operator entry/confirmation, cleanup receipt and terminal-bump retirement handoff encoding; retain separate unresolved broker obligations. The selected per-act operator waiver is not a caller-supplied or standing waiver. | No unsafe retry, destructive adoption or implicit absence; pending effects retain identity/quota reservations. |
| Q3 authority-source implementation | Implement the [common interface and selected local-v0 providers](spec/station-effect-receipts.md#6-accepted-local-v0-authority-sources), versioned source-label policy with operator pins, fresh evidence binding and both-lock activation guard. Implement the [root-only issuer, canonical record reader and qualified account directory](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record), reviewed policy maintenance selection/`no_launcher` update and module support/range provenance. Root qualification verifies policy/record protection, cron/at denial, no linger and every recorded binding; a flag alone never admits. Provider replacement is configuration only for the backend; later providers require publication/qualification. | Unknown/stale evidence or missing policy/deny entry/linger control refuses qualification. No backend wiring or operator entry is claimed by the source decision. |
| Q4 — composition and physical start | Local v0 uses the root-approved digest-pinned skeleton provider with no launcher. Curator must later publish control mapping, trust-pin encoding and composition/start interlock for each runtime through the same interface; launcher must qualify complete effective-control discovery, approved updates and exact checked-object use on every start/resume. | Account `active` is not station usable; no launcher activation is claimed. |
| Q5 — Linux qualification window | Owner review/execution of the single fixed root fixture script in stations-v0.md §10; later disposable root backend qualification for account tools, process absence, complete outside-home UID-object inventory, persistence denial and temp hygiene. Fixture setup cannot prove the unimplemented backend. | Exact root ownership/group tests and all backend tests remain PENDING; unprivileged permission surrogates have explicit limits. |

### A3 update publication gates

Publish the supported repository/package/closure profile and stable verifier
custody; protected transaction/exclusion and maintenance-journal encoding;
finite resource/freshness bounds and clock policy; P7 deadline/containment owner;
and owner/curator notification adapters and qualified root recovery. Integrate
the A2 macOS §7.1 companion reference when it lands. The
[A3 qualification plan](spec/upgrade-requalification.md#7-qualification-plan--negative-cases-first)
and root outline are PENDING. Station admission stays closed until A3 is landed,
implemented and qualified; no timer, missing-evidence fallback, automatic keyring
rotation, admission reopening or generation changes are authorized.

There is no open choice about account pooling, station-readable private keys
or station ownership of managed-home ancestors: public CIP-0024 decisions
already forbid those. Keymaker/broker own their separate key/credential state;
account retirement alone does not recall issued signatures/tokens or revoke a
persistent identity.

## Core implementation deployment gates

The [Go core contract](docs/station-core.md) implements closed v2 storage,
immutable intent/receipt histories, per-effect unlocked flights, current
versioned authority checks and exact restoration boundary types. The
[v2 OS receipt contract](spec/station-effect-receipts.md#8-implementation-and-review-gates)
still requires Linux/backend qualification, maintenance incident reconciliation
and reviewed nonempty-v1 provenance migration. The gated maintenance API accepts
only approved empty genesis and preserves its original bytes. The concrete
protected operator consent/broker-obligation encodings are implemented at the
issuer boundary; authenticated issuance and root installation remain pending.
Production still requires the Linux backend,
qualified sudo/service-identity adapter, authoritative cleanup admission,
authenticated exact-pair Keymaker re-admission/binding receipts with a pinned
activation guard, and external restore/migration custody. Production bump is
closed as `bump_key_admission_unconfirmed` until the joint Keymaker contract
is accepted; policy cannot enable it. The binary links the Linux
backend and supplies the reviewed files-only Environment. It refuses new work
without protected matching qualification evidence; tests do not qualify a host.
A writer crash retaining `writer.pending` requires the generation format's
explicit root reconciliation before same-effect recovery can proceed.

## Linux receipt qualification gates

The [Linux receipt primitive boundary](internal/linuxos/README.md#receipt-primitive-boundary)
now separates restored identity evidence, live exclusive stage handles and fresh
qualification observations. Production still needs an authenticated core adapter,
a qualified complete NSS/membership provider with protected local account-database
agreement/exclusion, and receipt-backed restart continuity. No name/inode-only
reconstruction of lost ownership handles is provided. Unproved objects remain
untouched in logical quarantine; root maintenance release is outside this API.
Root:S installation/quarantine and crash durability, deployed policy schema and
[root-run record issuer/reader and NSS module qualification](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record),
effective cron/at denial/allow precedence for every station name,
and logind/no-running-manager checks remain pending host qualification. These
checks do not enable bump, policy installation or account activation.

The Linux adapter links the issuer and retained root qualification-record reader.
The qualified directory boundary supports files with explicit reviewed loader,
configuration and exclusion capabilities. The
[bounded direct userdb collector](docs/linux-backend.md#direct-provider-completion-and-nss-agreement)
requires a matching protected closure, clean completion from every recorded
allocator, strict ranges and records, and independent NSS agreement. Unknown
metadata, unsupported records and nonterminating providers refuse admission.
Actual provider deployment, complete reviewed range provenance,
maintained exclusion and root/boot qualification remain pending. The production adapter
refuses without them; `qualified: true` alone never admits. Approved skeleton
reading, full inventory-scope configuration and maintained local guards are
implemented; their deployed completeness still requires review. Lost live stage/publication handles require
qualified continuity or root maintenance, never pathname/inode adoption. See
[the adapter boundary](docs/linux-backend.md).


## Qualification deployment gates

The issuer, protected record reader and reviewed production environment
are implemented. Privileged installation, real root account behavior and live
unit renewal remain pending the owner procedure in `docs/linux-backend.md`.
The systemd closure and direct collector are implemented; a `files systemd` host
requires protected provider capabilities and clean completion from each allocator.
The production adapter supplies those capabilities through the reviewed deployment
profile; owned fixtures establish runtime integration, not privileged host acceptance.
The actual loader ABI/search closure, full inventory roots, effective
unit/drop-in load scope and exclusion of other root writers require owner review;
missing facts refuse. Unsupported cron-owner resolution also remains refusal.
These gates do not resolve Keymaker bump admission or cleanup authority.

## macOS station backend gates

The [macOS draft](spec/stations-macos-v0.md) preserves shared lifecycle and
journal guarantees; it does not qualify an OS adapter. [Read-only observations](spec/stations-macos-facts.md)
on macOS 27.0.1/26A434 dated 2026-10-24 settle diagnostic details only. Native
qualification and mutation remain PENDING-VERIFY; root fixtures remain
PENDING-HOST. P5 settles scope to explicitly named trusted tasks with soft
limits (hard-limit tasks refused there or run on Linux). P7 settles immediate
new-start closure on revocation and verified narrowing or stop within a
published deadline; mechanisms and deadline still require qualification.

The recommendations below are proposals for resolving M1–M7, not approvals or
new owner decisions. P5 and P7 retain their settled scope; the recommended
mechanisms, profiles and procedures remain unselected and unqualified.

| Gate | Open decision/evidence after F1–F8 | Safe state |
|---|---|---|
| M1 — Supported directory profile | Recommendation: approve exact finite local/system/synthetic providers, collision/range and implicit-group rules, including review of PROPOSED range 30000–59999. Own lifecycle-wide authentication/token/volume-owner exclusions across later Platform SSO, MDM and bootstrap-token changes. Require distinct lifetime evidence for login-window hiding, password/session denial, Secure Token, FileVault and volume ownership; hidden or tokenless at creation is insufficient | Unknown provider/membership or privilege transition closes qualification; no host range approved |
| M2 — Filesystem root and metadata | Recommendation: select R/volume and case/alias profile; establish ACL-free, metadata and hardlink-protection feasibility before promising equivalence, retaining root/TCC visibility bounds. An unavailable primitive requires an explicit architecture decision, never stripping OS policy | No installation or complete-inventory claim; do not strip observed OS metadata |
| M3 — Shared platform binding and revocation | Recommendation: jointly publish typed OpenDirectory/dyld/boot/launchd and latest-invocation proof; diagnostic print/PID/exit fields are insufficient. Resolve P7 with the finite deadline, clock and suspend/wake semantics, triggering event, affected-work set, response owner, verified-narrowing preconditions and stop-completion evidence. Restart, resume or failed narrowing MUST NOT restart the response clock | Linux codec unchanged; immediate new-start closure under P7; no macOS issuer/reader or running-work admission before qualification |
| M4 — Cleanup/stop coverage | Recommendation: publish complete credential (real/effective/saved UID), holder, respawn and Mach scopes, actual per-user /var/folders mapping including stale UUID mappings, detached storage and every outside-home provider. Diagnostic ps/SysV/cron views are insufficient; unknown ownership never authorizes deletion | No removal/reuse from incomplete evidence; bump stays closed |
| M5 — Native journal/durability | Recommendation: jointly qualify native reader/writer locking, sync/publication/crash semantics, original budgets and external restore custody with direct consumers. APFS metadata observations do not establish these guarantees | No production journal writer/consumer claim |
| M6 — Key, root qualification and task scope | Recommendation: select the root-test host/procedure separately; publish task names/soft bounds, qualify admission and static UID-range deny, and retain the shared Keymaker pre-active provision/confirm activation gate. P5 is settled scope: explicitly named trusted soft-limit tasks; hard-limit tasks refuse or use Linux, with no waiver | `user.bump` closed; no mutations, execution or hard-limit claim from read-only facts |
| M7 — Authentic update/requalification | Recommendation: publish authentic publisher/target/trust policy, update-writer exclusion including automatic/MDM/background updates, installed seal/Cryptex evidence, authorized pin-transition and interrupted failure/rollback rules. Qualify reviewed root verification and the five named MacUpdate cases, each paired with an authentic pre-approved-target control; history and a reported sealed snapshot are insufficient | No automatic acceptance of unverified updates; admission closed and P7 response applies on revocation |

## Boot service validation after the openat2 sandbox correction

The old qualification service's `RestrictSUIDSGID=yes` denies required openat2
reads on systemd 259. The corrected profile and stage-coded diagnostics have an
unprivileged live reproduction and preflight hook, documented in
[qualification diagnostics](docs/qualification-diagnostics.md). The specific
previous root failure had no stage trace; a corrected delivery with regenerated
pins still requires the owner to run initial qualification and successful boot
renewal, preserving diagnostics on refusal. Nonroot preflight is no privileged
acceptance evidence.

## A3 evidence implementation gates

The [evidence implementation](docs/update-evidence.md) adds a recorder, local
archive-chain verifier and uninstalled hook examples. It supplies neither an
automatic pin protocol nor host qualification. Before deployment:

- Choose and qualify the independent dpkg terminal observer. An in-process post
  hook cannot observe its still-running parent's exit; `post-observed` cannot
  become terminal success without an authenticated independent observation.
  Supervisor and external process/audit observer options and their requirements
  are recorded in the implementation document. This blocks end-to-end recorder
  acceptance with the sample hooks alone.
- Wire the pinned public timeconf collector entry/policy into the service and
  qualify durable time continuity. Unknown/untrusted time refuses. Release age
  seven days, future-Date skew five minutes and P7 response five minutes are
  owner-confirmed and fixed by native profile validation.
- Qualify the complete independently held verifier/decoder closure, pinned key
  validity/revocation policy, exact Ubuntu/archive/package mapping, and native
  hook/ownership/exclusion behavior. The multi-repository composition library
  covers the finite approved source set; its actual deployed profile still
  requires explicit qualification.
- Implement the A3 §4 maintenance journal and qualifier lock handoffs, candidate
  diff checks, accepted frontier, original evidence retention and boot binding.
- Integrate authenticated admission/containment and owner/curator pending-delivery
  receipts before any admission claim. A maintenance assertion alone is not P7
  containment evidence.
