# Internal Go integration seams

There is no loadable plugin registry or plugin CLI in this module. The existing
extension points are Go interfaces under `internal/manager`; Go's internal
package boundary limits their importers. Extending them requires source wiring
in an allowed importer, not installing a plugin. Treat the following as
development guidance, not an available deployment action.

## Authority source: implement, wire, verify

1. Implement `AuthoritySource.Evaluate(context.Context, AuthorityInput)
   (AuthorityEvidence, error)` from
   [sources.go](../../../../internal/manager/sources.go). Preserve the full input
   binding, including source/version, purpose, caller, identity, effect/intent,
   policy/tail/fence/boot basis and fresh challenge. Admission requires verdict
   `admit`, identical input digest, the exact `scopeDigest` of purpose/identity/
   effect, a lowercase SHA-256 evidence digest, future `Until` and a live
   `ActivationGuard`. `evidenceOK` checks these; a digest alone supplies no facts.
   `scopeDigest` is private: use the same package or reproduce its exact CCJ
   object with keys `purpose`, `identity`, `effect` (the last is `EffectKey`) in
   an allowed importer, without assuming an exported helper.
2. Wire the implementation into `Engine.Sources`, keyed by the exact
   `SourceSelection.Source`. Configure `Policy.Sources` with one
   `{purpose,source,version}` for each of `host_qualification`,
   `cleanup_admission`, `managed_content`, `persistence_denial`, `process_fence`
   and `activation_guard`. `validateSources` requires all six without duplicate
   purposes and a lowercase SHA-256 version; it is not a dynamic registration
   API. `execution.authorityFor` in
   [flights.go](../../../../internal/manager/flights.go) performs map lookup and
   revalidates evidence and basis. A missing provider refuses
   `qualification_required`.
3. Keep evidence preparation outside state locks. The returned guard must do
   bounded local validation through final use and release; retain its acquisition
   context until release. Follow `timedGuard` and
   [station-core.md](../../../../docs/station-core.md); remote calls, account
   tools and scans do not belong in final guards.
4. For fixture verification, follow `setup` in
   [engine_test.go](../../../../internal/manager/engine_test.go): it injects
   `Engine.Sources` and a fake backend. `evidenceSource` and
   `TestUnknownAuthorityCannotQualify` in
   [v2_core_test.go](../../../../internal/manager/v2_core_test.go) show replacement
   and missing/unknown/version/scope/expiry controls with no allocation on
   refusal. Keep an admitted neighbor; use `TestStalePreparedEvidenceRechecked`,
   `TestAuthorityGuardContextLifetime` and `TestExternalIOHoldsNoStateLock` as
   patterns for drift, guard release and independent progress. These fixtures
   exercise core contracts; they do not qualify real accounts or deployment.

Production [run](../../../../cmd/swarma-user-manager/main.go) wires only
`local-v0` as `LocalV0Source` with `FilePolicyReader`, the Linux backend and
`FileOperatorVerifier`. Merely adding another policy label cannot instantiate a
provider. `LocalV0Source.Evaluate` itself requires `local-v0`, selected purpose/
version, protected current policy and validated backend evidence; it has no
permissive fallback. Its cleanup path revalidates the exact operator act.

## Backend adapter

Implement the full `Backend` interface in
[contracts.go](../../../../internal/manager/contracts.go) and inject it through
`Engine.Backend`. Keep `Plan` read-only and expose each individual write as an
intent; `Execute` consumes the admitted `Attempt` and returns explicit stopped/
outcome/object evidence. `Restore` must prove the original reserved identity and
ownership, rather than adopt an NSS match. `Evidence` supplies current facts;
`CommitReady` returns the maintained local guard. Follow the full obligations in
[station-core.md](../../../../docs/station-core.md) and the existing
[Linux adapter](../../../../internal/linuxbackend/backend_linux.go).

Use `fakeBackend` in [v2_backend_test.go](../../../../internal/manager/v2_backend_test.go)
and `interceptBackend` in `v2_core_test.go` for admitted controls, unknown workers,
foreign receipts and stale preparation. The ordinary entrypoint constructs its
Linux backend directly; changing a policy cannot replace it. No configuration,
test guard, plugin seam or fake evidence can enable `Engine.bumpConfirmed` in a
production build or replace host/provider qualification.
