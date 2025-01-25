package io

import (
	"container/heap"
	"io"
	"sync"
)

type (
	replicateReaderManager struct {
		l          sync.Locker
		readers    readerPriorityQueue
		buf        []byte
		base       int
		r          io.Reader
		alreadyEOF bool
	}

	readerPriorityQueue []*replicateReader

	replicateReader struct {
		manager *replicateReaderManager
		offset  int
		index   int
	}
)

func (repReaderManager *replicateReaderManager) readFromReader(p []byte, skipCopyingToBuf bool) (n int, err error) {
	if repReaderManager.alreadyEOF {
		return 0, io.EOF
	}
	n, err = repReaderManager.r.Read(p)
	if !skipCopyingToBuf {
		repReaderManager.buf = append(repReaderManager.buf, p[:n]...)
	}
	repReaderManager.alreadyEOF = repReaderManager.alreadyEOF || err == io.EOF
	return n, err
}

func (repReaderManager *replicateReaderManager) leastOffset() int {
	return repReaderManager.readers[0].offset
}

func (repReaderManager *replicateReaderManager) furthestOffset() int {
	return repReaderManager.base + len(repReaderManager.buf)
}

func (repReaderManager *replicateReaderManager) moveIfNeeded() {
	if repReaderManager.base+repReaderManager.furthestOffset() < repReaderManager.leastOffset()*2 {
		start := repReaderManager.leastOffset() - repReaderManager.base
		cnt := copy(repReaderManager.buf, repReaderManager.buf[start:])
		repReaderManager.buf = repReaderManager.buf[:cnt]
		repReaderManager.base = repReaderManager.leastOffset()
	}
}

func (readers readerPriorityQueue) Len() int {
	return len(readers)
}

func (readers readerPriorityQueue) Less(i int, j int) bool {
	return readers[i].offset < readers[j].offset
}

func (readers readerPriorityQueue) Swap(i int, j int) {
	readers[i], readers[j] = readers[j], readers[i]
	readers[i].index = i
	readers[j].index = j
}

func (readers *readerPriorityQueue) Push(x any) {
	repReader := x.(*replicateReader)
	repReader.index = readers.Len()
	*readers = append(*readers, repReader)
}

func (readers *readerPriorityQueue) Pop() any {
	n := readers.Len()
	old := *readers
	repReader := old[n-1]
	old[n-1] = nil       // don't stop the GC from reclaiming the item eventually
	repReader.index = -1 // for safety
	*readers = old[0 : n-1]
	return repReader
}

func (repReader *replicateReader) advanceOffset(n int) {
	repReader.offset += n
	heap.Fix(&repReader.manager.readers, repReader.index)
}

func (repReader *replicateReader) readFromBuf(p []byte) int {
	start := repReader.offset - repReader.manager.base
	n := copy(p, repReader.manager.buf[start:])
	repReader.advanceOffset(n)
	return n
}

func (repReader *replicateReader) Read(p []byte) (n int, err error) {

	repReader.manager.l.Lock()
	defer repReader.manager.l.Unlock()

	if len(repReader.manager.readers) == 1 {
		if repReader.offset == repReader.manager.furthestOffset() {
			return repReader.manager.readFromReader(p, true)
		}
		return repReader.readFromBuf(p), nil
	}

	if repReader.offset == repReader.manager.furthestOffset() {
		n, err = repReader.manager.readFromReader(p, false)
		repReader.advanceOffset(n)
		return n, err
	}

	n = repReader.readFromBuf(p)
	repReader.manager.moveIfNeeded()
	return n, nil
}

func (repReader *replicateReader) Close() error {

	repReader.manager.l.Lock()
	defer repReader.manager.l.Unlock()

	heap.Remove(&repReader.manager.readers, repReader.index)
	return nil
}

// The `Close()` method of the returned `ReadCloser`s is only required to be
// invoked for partial reads, otherwise the `buf` will grow unexpectedly.
func ReplicateReader(r io.Reader, n int) []io.ReadCloser {
	manager := replicateReaderManager{
		l:          new(sync.Mutex),
		readers:    make([]*replicateReader, n),
		buf:        nil,
		base:       0,
		r:          r,
		alreadyEOF: false,
	}
	readers := make([]io.ReadCloser, n)
	for i := range readers {
		manager.readers[i] = &replicateReader{
			manager: &manager,
			offset:  0,
			index:   i,
		}
		readers[i] = manager.readers[i]
	}
	return readers
}
