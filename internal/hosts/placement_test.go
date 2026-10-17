package hosts

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scriptedProber map[string]any // Capacity or error, by host name

func (s scriptedProber) Capacity(_ context.Context, h Host) (Capacity, error) {
	switch v := s[h.Name].(type) {
	case Capacity:
		return v, nil
	case error:
		return Capacity{}, v
	default:
		return Capacity{}, errors.New("unscripted host")
	}
}

func room(freeMiB, sandboxes int) Capacity {
	return Capacity{MaxSandboxes: 10, Sandboxes: sandboxes, MaxCPUs: 32, CPUs: 0, MaxMemoryMiB: 65536, MemoryMiB: 65536 - freeMiB}
}

var small = Demand{CPUs: 2, MemoryMiB: 4096}

func TestPlacePicksMostFreeMemory(t *testing.T) {
	got, err := Place(context.Background(), []Host{sampleHost("a"), sampleHost("b"), sampleHost("c")}, scriptedProber{
		"a": room(8192, 0), "b": room(32768, 5), "c": room(16384, 0),
	}, small)
	require.NoError(t, err)
	assert.Equal(t, "b", got.Name)
}

func TestPlaceTieBreaksBySandboxesThenName(t *testing.T) {
	got, err := Place(context.Background(), []Host{sampleHost("c"), sampleHost("b"), sampleHost("a")}, scriptedProber{
		"a": room(16384, 3), "b": room(16384, 1), "c": room(16384, 1),
	}, small)
	require.NoError(t, err)
	assert.Equal(t, "b", got.Name)
}

func TestPlaceSkipsUnreachableAndFull(t *testing.T) {
	full := room(65536, 10) // no sandbox slot left
	got, err := Place(context.Background(), []Host{sampleHost("a"), sampleHost("b"), sampleHost("c")}, scriptedProber{
		"a": errors.New("dial timeout"), "b": full, "c": room(4096, 0),
	}, small)
	require.NoError(t, err)
	assert.Equal(t, "c", got.Name)
}

func TestPlaceDistinguishesFullFromUnreachable(t *testing.T) {
	cpuBound := room(65536, 0)
	cpuBound.CPUs = 31
	_, err := Place(context.Background(), []Host{sampleHost("a"), sampleHost("b")}, scriptedProber{
		"a": errors.New("refused"), "b": cpuBound,
	}, small)
	assert.ErrorIs(t, err, ErrAllFull)

	_, err = Place(context.Background(), []Host{sampleHost("a")}, scriptedProber{"a": errors.New("refused")}, small)
	assert.ErrorIs(t, err, ErrUnreachable)

	_, err = Place(context.Background(), nil, scriptedProber{}, small)
	assert.ErrorIs(t, err, ErrNoCandidates)
}

func TestFitsChecksEveryLimitInclusively(t *testing.T) {
	c := Capacity{MaxSandboxes: 2, Sandboxes: 1, MaxCPUs: 8, CPUs: 6, MaxMemoryMiB: 8192, MemoryMiB: 4096}
	assert.True(t, c.Fits(Demand{CPUs: 2, MemoryMiB: 4096}))
	assert.False(t, c.Fits(Demand{CPUs: 3, MemoryMiB: 4096}))
	assert.False(t, c.Fits(Demand{CPUs: 2, MemoryMiB: 4097}))
	c.Sandboxes = 2
	assert.False(t, c.Fits(Demand{CPUs: 1, MemoryMiB: 1}))
}

func TestPlaceHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Place(ctx, []Host{sampleHost("a")}, scriptedProber{"a": room(16384, 0)}, small)
	assert.ErrorIs(t, err, context.Canceled)
}
