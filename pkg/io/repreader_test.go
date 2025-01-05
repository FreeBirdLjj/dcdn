package io

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplicateReader(t *testing.T) {

	t.Parallel()

	t.Run("a reader's partial read should not affect other readers' reads", func(t *testing.T) {

		t.Parallel()

		s := "abcdefghijklmnopqrstuvwxyz"
		readers := ReplicateReader(strings.NewReader(s), 2)

		_, err := readers[0].Read(make([]byte, 10))
		require.NoError(t, err)
		readers[0].Close()

		content, err := io.ReadAll(readers[1])
		require.NoError(t, err)
		assert.Equal(t, s, string(content))
	})
	t.Run("should all succeed when readers read & close in a random order", func(t *testing.T) {

		t.Parallel()

		n := 20
		s := strings.Repeat("abcdefghijklmnopqrstuwxyz", n)

		readers := ReplicateReader(strings.NewReader(s), n)
		results := make([]string, n)

		wg := sync.WaitGroup{}
		wg.Add(n)

		for i, reader := range readers {
			go func() {
				defer wg.Done()
				defer reader.Close()
				result := bytes.Buffer{}
				_, err := io.CopyBuffer(&result, reader, make([]byte, i+1))
				require.NoError(t, err)
				results[i] = result.String()
			}()
		}

		wg.Wait()

		assert.Equal(t, slices.Repeat([]string{s}, n), results)
	})
}
