# A3 evidence implementation

This implements evidence for [A3](../spec/upgrade-requalification.md), not an
automatic pin decision, admission controller or deployed host qualification.

## Recorder format and crash boundary

`internal/updateproof` stores `station-update-recorder/1` in a dedicated,
installer-created root-owned 0700 directory with a root-owned 0600, single-link,
empty `recorder.lock`. The directory is separate from generation and OS-effect
journals. It does not auto-create or repair missing/corrupt state.

Events use canonical Go JSON struct field order, no trailing whitespace, and
closed decoding (unknown fields/trailing values refuse). Names are consecutive
20-digit global sequences plus `.json`. Each event binds format, sequence,
previous event SHA-256, begin/end phase, typed ID, parent, authenticated hook
instance token, complete sorted package/leaf snapshot and completion status.
IDs contain boot identity, monotonic sequence and aggregate/invocation kind;
tokens deduplicate an instance but never replace its ID. Aggregates keep ordered
invocation membership through their begin events. Direct dpkg has no aggregate.
The public encoding is reviewed with this implementation; no existing codec is
extended.

A per-operation exclusive flock serializes validation/allocation/append. Readers
validate every sequence, predecessor, canonical byte representation and legal
state transition. Snapshot acquisition/external calls occur outside that lock.
Limits bound journal bytes, entry count and snapshot members. Exhaustion refuses
without pruning history. Each new event uses exclusive no-follow creation,
file sync then parent sync before success. A partial/unsynced event is not a
successful allocation or completion; a retained torn file blocks recovery.
Conflicting reuse cannot append, and identical end events append no second effect.

Boot scan compares the full current package/leaf snapshot with the final retained
snapshot and returns every complete unreconciled invocation, in aggregate order.
A missing apt post hook can yield evidence only when its entire invocation list
is complete and the current endpoint agrees. Incomplete dpkg, missing attribution,
unknown chronology, triggers or any unrecorded transition refuses. Scanning does
not manufacture an acceptance frontier or reopen admission. Initial baseline and
later accepted frontiers require explicit qualification and the next slice.
