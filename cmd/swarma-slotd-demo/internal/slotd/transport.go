package slotd

import (
	"bufio"
	"bytes"
	"io"
	"strconv"
	"sync"
)

// readFrame bounds the JSON object separately from its required terminating LF.
// The transport must set a five-second socket deadline before calling it.
func readFrame(reader io.Reader) ([]byte, errorCode) {
	r := bufio.NewReaderSize(reader, maxRequestBytes+2)
	b, err := r.ReadSlice('\n')
	if err != nil || len(b)-1 > maxRequestBytes {
		return nil, badRequest
	}
	return bytes.Clone(b), ""
}

func authorizePeer(peerUID, callerUID uint32) errorCode {
	if peerUID != callerUID {
		return forbiddenPeer
	}
	return ""
}

type slotLocks struct {
	locks [10000]sync.Mutex
}

// tryLock never waits. Invalid slots cannot index the lock array.
func (l *slotLocks) tryLock(slot string) (unlock func(), code errorCode) {
	if !slotPattern.MatchString(slot) {
		return nil, invalidSlot
	}
	n, _ := strconv.Atoi(slot)
	if !l.locks[n].TryLock() {
		return nil, busy
	}
	return l.locks[n].Unlock, ""
}
