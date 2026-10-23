#!/bin/sh
# Reviewed manual writer; Linux, POSIX sh, coreutils, util-linux flock, pinned checker.
# Usage: manual-journal.sh TOOL init DIR
#        manual-journal.sh TOOL append DIR FLOOR_SEQ FLOOR_HASH MIN_UID MAX_UID UID GENERATION STATE UTC_TIME
#        manual-journal.sh TOOL reconcile DIR FLOOR_SEQ FLOOR_HASH
#        manual-journal.sh TOOL rollback-genesis DIR
# TOOL and DIR must be absolute protected paths. Reconcile needs the incident review in the spec.
set -eu
umask 022
if [ "$#" -lt 3 ]; then
    echo 'journal_usage' >&2
    exit 2
fi
tool=$1
operation=$2
dir=$3
shift 3
case "$tool:$dir" in
    /*:/*) ;;
    *) echo 'journal_usage' >&2; exit 2 ;;
esac
case "$operation" in
    init)
        if [ "$#" -ne 0 ]; then exit 2; fi
        "$tool" init "$dir"
        ;;
    rollback-genesis)
        if [ "$#" -ne 0 ]; then exit 2; fi
        "$tool" intent "$dir"
        exec 8<"$dir/gate.lock"
        flock -x -w 5 -E 75 8
        exec 9<"$dir/data.lock"
        flock -x -w 5 -E 75 9
        "$tool" rollback-genesis-locked "$dir" 0 0000000000000000000000000000000000000000000000000000000000000000
        ;;
    append|reconcile)
        if [ "$operation" = append ]; then
            if [ "$#" -ne 8 ]; then exit 2; fi
            # No auto-clear trap: errors before verified durable commit keep admission closed.
            "$tool" intent "$dir"
        else
            if [ "$#" -ne 2 ]; then exit 2; fi
        fi
        # '<' never creates a missing lock. Normal writes share one marker deadline, not per-lock waits.
        exec 8<"$dir/gate.lock"
        exec 9<"$dir/data.lock"
        if [ "$operation" = append ]; then
            "$tool" lock-writer "$dir"
            "$tool" append-locked "$dir" "$@"
            "$tool" finish-intent "$dir" "$1" "$2"
        else
            # Reviewed incident reconciliation is outside the normal append budget.
            flock -x -w 5 -E 75 8
            flock -x -w 5 -E 75 9
            "$tool" verify-locked "$dir" "$1" "$2"
            "$tool" clear-intent "$dir" "$1" "$2"
        fi
        # Exit closes both descriptors; finish-intent already unlocks before diagnostic output.
        ;;
    *) echo 'journal_usage' >&2; exit 2 ;;
esac
