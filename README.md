# swarma-user-manager

Two minimal privileged components for agent systems. Each runs as root for one operation at a time, through a sudoers rule that admits only its absolute path with no arguments, and performs a closed set of host operations:

- **swarma-user-manager** creates, lists and retires per-agent, per-service and qualified workplace OS accounts, and (next) installs per-account firewall rules so that an agent's traffic can leave only through its network profile;
- **swarma-user-launcher** starts one approved executor under one active agent or qualified workplace account, so that an unprivileged dispatcher can run an agent as that account without general `sudo` rights.

**Status: design in progress.** Nothing is implemented yet. The specification is [`spec/helper.md`](spec/helper.md); diagrams are in [`diagrams/`](diagrams/).

## Principles

- Closed operation schemas read from stdin (`swarma-user-manager helper-op/1`, `swarma-user-manager launch-op/1`), never free-form arguments, commands or environment.
- Per-caller policy: installers manage configured service accounts, dispatchers manage only the agents and qualified workplaces they created. The helper's `operator` UID is the protected service account `swarma-operator`; it and the mandatory read-only `swarma-observer` never host a harness session.
- Operator signing authority belongs to `swarma-operator`. Phone-first acts use a biometric-gated operator device key over tailnet SSH, with a forced operator command and no shell; the terminal fallback uses password-authenticated sudo with `timestamp_timeout=0`. Operator helper sudo is authenticated and non-cached; `NOPASSWD` stays only for dispatcher helper/launcher rules. Widening acts require exact-content confirmation and are refused inside agent sessions; narrowing acts need authentication only. Reads of status, grants, accounts and bindings use `swarma-observer` without confirmation. Unpublished entry/signing/read interfaces remain publication gates ([§11](spec/helper.md#11-installation), [§14](spec/helper.md#14-open-questions)).
- The helper chooses account names and UIDs from its own ranges; every creation gets a fresh random 128-bit generation that is never reused (R-GEN).
- It acts only on accounts it created (a root-owned ledger), never on pre-existing accounts, and works on files through descriptors without following links.
- One lock protects state transitions; dependency recovery and bounded retirement batches yield to unrelated controls. Creation rolls back on failure; retirement moves forward from its commit point; every operation leaves an audit line naming the caller.
- Retirement deletes the home after verified quiescence and declared-key cleanup; only a closed-schema service-generated metadata export may remain. Keeping a home is a separate explicit operator operation requiring authentication plus exact-content confirmation; its confidentiality is not guaranteed ([§4.4.1](spec/helper.md#441-retirement-deletion-and-metadata-export)).
- `effect.observe` exposes six receiver-owned evidence states under the journal lock; expired or missing evidence is `unavailable`, never proof of absence ([§4.6](spec/helper.md#46-lock-journal-and-idempotency)).
- The launcher preserves trusted handles through their last use and delivers completely staged bounded immutable bytes on read-only FD3; the per-platform mechanism remains publication work ([§7](spec/helper.md#7-the-launcher-swarma-user-launcher)).
- `exec.stop` and retirement signal and verify every process of the current generation UID. Latest-receipt fencing prevents old stops from signalling successors; unfinished stops continue under their own effect ID (R-OUTCOME). `exec.stop` proves process absence only; the session host's recovery owns the separate harness native-lock check ([§4.7](spec/helper.md#47-execstop)).
- Retirement is entirely local; dispatcher/operator broker unbind remains a separate confirmed effect. Direct operator retirement retains any unresolved binding-cleanup obligation ([§4.4](spec/helper.md#44-userretire)).
- The process fate table and replaced-daemon writer fence live beside R-FD3 in [§7](spec/helper.md#7-the-launcher-swarma-user-launcher); concrete containment/unit configurations remain qualification gates.
- Cross-account workspaces have standalone repositories with private `.git`, configuration and hooks; linked worktrees remain within one account, including today's board workflow.
- v1 adds mandatory workplace enforcement, service egress rows and machine-owned Curator-to-network binding with served-policy digest checks ([§8](spec/helper.md#8-firewall-per-account-v1)). Unpublished formats, schedules and platform mechanisms remain explicit activation gates.
- Later: it re-verifies the signed grant behind each request instead of trusting the configured policy alone.

## How it fits

- [swarma-dispatcher](https://github.com/relux-works/swarma-dispatcher), under its own service account, creates an agent's account with the helper, binds that account's generation in swarma-credential-broker, and starts the agent's executor through the launcher; the executor then obtains its credential lease from the broker itself.
- swarma-credential-broker runs under a service account the helper creates, and reads the helper's ledger to check generations.
- The dispatcher is a Unix-socket service from its first slice and calls the helper and launcher through sudo. It is the only launcher caller. In the gated SH2+ design, the host requests `host_start`/`host_stop` from the dispatcher under a session-scoped host admission permit. Successors require session lifecycle authorisation and confirmed absence of the previous claim; each physical start keeps its claim/fence/receipt interlock. Joint publication remains required ([§7](spec/helper.md#7-the-launcher-swarma-user-launcher)).

## Diagrams

PlantUML sources map the current [specification](spec/helper.md#appendix-b-diagrams). All figures show unimplemented design phases, process identities, state owners and refusal/recovery boundaries. Visible notes preserve unspecified behavior and open decisions; SH2 launch authority is not activated.

| Audit row | Figure | Spec |
|---|---|---|
| M-UM1 | [Privileged components](diagrams/components.puml) | [§1](spec/helper.md#1-purpose), §§2–3, 4.6, 6–9 |
| M-UM2 | [Launch and authorised stop](diagrams/launch.puml) | [§7](spec/helper.md#7-the-launcher-swarma-user-launcher), §4.7 |
| M-UM2 | [Provision, retire and recovery](diagrams/provision-retire-recovery.puml) | [§4.3](spec/helper.md#43-usercreate), §§4.4–4.6 |
| M-UM3 | [Account lifecycle](diagrams/account-lifecycle.puml) | [§4.2](spec/helper.md#42-lifecycle), §4.6 |
| M-UM3 | [Receipt evidence and retirement fate](diagrams/receipt-archive-states.puml) | [§4.4.1](spec/helper.md#441-retirement-deletion-and-metadata-export), §§4.7, 7 |
| M-UM4 | [Storage layout and owners](diagrams/storage-layout.puml) | [§4.0](spec/helper.md#40-layout), §§6–7, 11 |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
