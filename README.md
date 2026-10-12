# swarma-user-manager

Two minimal privileged components for agent systems. Each runs as root for one operation at a time, through a sudoers rule that admits only its absolute path with no arguments, and performs a closed set of host operations:

- **swarma-user-manager** creates, lists and retires per-agent and per-service OS accounts, and (next) installs per-account firewall rules so that an agent's traffic can leave only through its network profile;
- **swarma-user-launcher** starts one approved executor under one active agent account, so that an unprivileged dispatcher can run an agent as that account without general `sudo` rights.

**Status: design in progress.** Nothing is implemented yet. The specification is [`spec/helper.md`](spec/helper.md); diagrams are in [`diagrams/`](diagrams/).

## Principles

- Closed operation schemas read from stdin (`swarma-user-manager helper-op/1`, `swarma-user-manager launch-op/1`), never free-form arguments, commands or environment.
- Per-caller policy: installers manage service accounts, dispatchers manage only the agents they created.
- The helper chooses account names and UIDs from its own ranges; every creation gets a generation that is never reused.
- It acts only on accounts it created (a root-owned ledger), never on pre-existing accounts, and works on files through descriptors without following links.
- One lock serialises everything; creation rolls back on failure, retirement moves forward from its commit point; every operation leaves an audit line naming the caller.
- Retirement archives never receive secrets: mandatory exclusions cannot be overridden, declared keys are destroyed before the walk, and unknown classification means deletion ([§4.4.1](spec/helper.md#441-archive-policy)).
- `exec.stop` proves process absence only; the session host's recovery owns the separate harness native-lock check ([§4.7](spec/helper.md#47-execstop)).
- Later: it re-verifies the signed grant behind each request instead of trusting the configured policy alone.

## How it fits

- [swarma-dispatcher](https://github.com/relux-works/swarma-dispatcher), under its own service account, creates an agent's account with the helper, binds that account's generation in swarma-credential-broker, and starts the agent's executor through the launcher; the executor then obtains its credential lease from the broker itself.
- swarma-credential-broker runs under a service account the helper creates, and reads the helper's ledger to check generations.
- In the gated SH2+ design, an authenticated session host presents a dispatcher-issued ticket to `swarma-user-launcher`, which redeems it once under the shared lock and journal. This route remains disabled until I4 is published ([§7](spec/helper.md#7-the-launcher-swarma-user-launcher)).

## Diagrams

PlantUML sources map the current [specification](spec/helper.md#appendix-b-diagrams). All figures show unimplemented design phases, process identities, state owners and refusal/recovery boundaries. Visible notes preserve unspecified behavior and open decisions; SH2 launch authority is not activated.

| Audit row | Figure | Spec |
|---|---|---|
| M-UM1 | [Privileged components](diagrams/components.puml) | [§1](spec/helper.md#1-purpose), §§2–3, 4.6, 6–9 |
| M-UM2 | [Launch and authorised stop](diagrams/launch.puml) | [§7](spec/helper.md#7-the-launcher-swarma-user-launcher), §4.7 |
| M-UM2 | [Provision, retire and recovery](diagrams/provision-retire-recovery.puml) | [§4.3](spec/helper.md#43-usercreate), §§4.4–4.6 |
| M-UM3 | [Account lifecycle](diagrams/account-lifecycle.puml) | [§4.2](spec/helper.md#42-lifecycle), §4.6 |
| M-UM3 | [Receipt evidence and archive fate](diagrams/receipt-archive-states.puml) | [§4.4.1](spec/helper.md#441-archive-policy), §§4.7, 7 |
| M-UM4 | [Storage layout and owners](diagrams/storage-layout.puml) | [§4.0](spec/helper.md#40-layout), §§6–7, 11 |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Authors: Ivan Oparin and Alexey Grigorev.
