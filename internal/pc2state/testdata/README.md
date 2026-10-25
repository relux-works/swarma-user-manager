# Public G4 comparison fixtures

These unchanged objects come from
[the key-service public vector manifest](https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/vectors/authority-root.json).
`manifest.json` retains each selected object's published ID, domain, length and
SHA-256, plus its source commit. Local paths select copies in this directory.

`TestPC2PublicVectors` checks all fourteen fixture hashes. Ten object/preimage
vectors also exercise manager round trips or pending-attempt construction.
The shared key-service-owned capacity inventory is intentionally rejected by
the manager-only codec. The transaction, original C0 and migration-history
objects supply origin rejection/acceptance and HistoryRef controls. Renamed
history/capacity wrappers used by other tests are derived fixtures, not claimed
to be additional published vectors.

The implementation was also compared read-only with that commit's
`internal/keymaker/authority_codec.go` and `authority_identity.go`: member sets,
caps, primitive types, phase/null unions, identity preimages and sorted-row
rules match for this subset. The manager's new history-transition helper is a
separate semantic check; shared codec acceptance does not prove complete
history, retained ordinals, provenance, durability or admission. Original
intent schema/provider binding remains a later integration question.
