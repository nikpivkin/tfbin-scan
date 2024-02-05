package tfplanscan

import (
	"context"
	"errors"
	"io"
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	terraformScanner "github.com/aquasecurity/trivy-iac/pkg/scanners/terraform"
)

type Scanner struct {
	inner *terraformScanner.Scanner
}

func New(options ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		inner: terraformScanner.New(options...),
	}
	return scanner
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	var results scan.Results
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		res, err := s.ScanFile(ctx, fsys, path)
		if errors.Is(err, noTerraformPlan) {
			return nil
		} else if err != nil {
			return err
		}
		results = append(results, res...)
		return nil
	}
	if err := fs.WalkDir(fsys, dir, walkFn); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Scanner) ScanFile(ctx context.Context, fsys fs.FS, filepath string) (scan.Results, error) {
	file, err := fsys.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return s.Scan(ctx, file)
}

func (s *Scanner) Scan(ctx context.Context, reader io.Reader) (scan.Results, error) {
	snap, err := readSnapshot(reader)
	if err != nil {
		return nil, err
	}
	memfs, err := snap.toFS()
	if err != nil {
		return nil, err
	}
	return s.inner.ScanFS(ctx, memfs, ".")
}
