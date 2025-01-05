package io

import (
	"io"
	"slices"
	"sync"
)

type (
	replicateReaderManager struct {
		l          sync.Locker
		readers    []*replicateReader
		buf        []byte
		base       int
		r          io.Reader
		alreadyEOF bool
	}

	replicateReader struct {
		manager *replicateReaderManager
		offset  int
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

func (repReaderManager *replicateReaderManager) furthestOffset() int {
	return repReaderManager.base + len(repReaderManager.buf)
}

func (repReaderManager *replicateReaderManager) moveIfNeeded() {
	if repReaderManager.base+repReaderManager.furthestOffset() < repReaderManager.readers[0].offset*2 {
		start := repReaderManager.readers[0].offset - repReaderManager.base
		cnt := copy(repReaderManager.buf, repReaderManager.buf[start:])
		repReaderManager.buf = repReaderManager.buf[:cnt]
		repReaderManager.base = repReaderManager.readers[0].offset
	}
}

func (repReader *replicateReader) advanceOffset(n int) {
	repReader.offset += n
	slices.SortFunc(repReader.manager.readers, func(l *replicateReader, r *replicateReader) int {
		return l.offset - r.offset
	})
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

	repReader.manager.readers = slices.DeleteFunc(repReader.manager.readers, func(reader *replicateReader) bool {
		return reader == repReader
	})

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
		}
		readers[i] = manager.readers[i]
	}
	return readers
}
