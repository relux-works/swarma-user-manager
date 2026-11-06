---
name: swarma-user-manager
description: Use Swarma User Manager's station requests and generation journal, or integrate its internal Go backend and authority sources. Use for this module, not generic OS account administration.
---

# Swarma User Manager

Choose the implemented interface before preparing a request or integration. The
[module README](../../../README.md) separates the station core, journal tools and
design contracts. Source availability does not establish an installed helper or
qualified host. Production provisioning remains gated; production bump is closed.

- For station account requests, read [lifecycle usage](references/lifecycle.md).
  The normal helper route consumes one closed canonical JSON request on stdin
  with no arguments. Do not turn specification operations into CLI subcommands.
- For offline generation metadata or a journal consumer, read
  [journal usage](references/journal.md). It includes a public inert fixture and
  its nearest refusal; byte verification alone never authorizes admission.
- For a backend or authority-source extension, read
  [Go integration](references/integration.md). These are internal compile-time
  seams with explicit wiring and fixture contracts, not a loadable plugin API.

Keep caller identity, allocation ownership, generation, current authority and
historical effect evidence distinct. A ledger projection, matching account name
or successful fixture cannot replace protected current evidence. Unknown process
or ownership evidence must stay unknown.

For deployment diagnosis, use the existing [qualification guide](../../../docs/qualification-diagnostics.md)
and [Linux backend guide](../../../docs/linux-backend.md); for update evidence,
use [its separate guide](../../../docs/update-evidence.md). Their maintenance
routes do not expand the normal request schema. Preserve closed activation gates
and report actual refusal codes and evidence limits.
