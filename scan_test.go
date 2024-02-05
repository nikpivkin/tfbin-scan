package tfplanscan

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_Scan(t *testing.T) {
	f, err := os.Open("testdata/tfplan.bin")
	require.NoError(t, err)
	defer f.Close()

	policyFS := os.DirFS("testdata/checks")

	scanner := New(
		options.ScannerWithEmbeddedPolicies(false),
		options.ScannerWithEmbeddedLibraries(true),
		options.ScannerWithPolicyNamespaces("user"),
		options.ScannerWithPolicyDirs("."),
		options.ScannerWithPolicyFilesystem(policyFS),
		options.ScannerWithRegoOnly(true),
	)

	result, err := scanner.Scan(context.TODO(), f)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	failed := result.GetFailed()

	assert.Len(t, failed, 2)

	ids := make([]string, 0, len(failed))

	for _, res := range failed {
		ids = append(ids, res.Rule().AVDID)
	}
	sort.Strings(ids)
	assert.Equal(t, []string{"ID001", "ID002"}, ids)
}
