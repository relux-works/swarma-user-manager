# Unresolved integration questions

1. The existing public `linuxos` filesystem interface cannot express the
   required slot-owned 0700 home and exclusive 0600 bootstrap. Its deletion
   methods also require the configured authority owner, whereas public
   `OpenRoot` fixes that owner to root. Resolve the implementation/reuse
   contract before adding these effects; do not change protocol ownership to
   fit the primitive or modify `internal/linuxos` in this change.
2. Receipt-backed restart retirement needs a qualified complete
   `AccountDirectory`, including independent NSS agreement and external-writer
   exclusion. The demo policy does not provide those deployment inputs.
   Matching a current name/UID is insufficient creation provenance. Resolve
   the admitted provider/recovery contract before adding account adoption or
   removal.

No end-to-end service or host qualification is claimed while these integration
questions remain open.
