package tfplanscan

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadSnapshot(t *testing.T) {
	f, err := os.Open("testdata/tfplan.bin")
	require.NoError(t, err)
	defer f.Close()

	snapshot, err := readSnapshot(f)
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	require.Len(t, snapshot.modules, 2)
}
