package secrets

import (
	"context"
	"path/filepath"
	"sort"

	"github.com/dsablic/codemium/internal/model"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Scan scans the directory for secrets using gitleaks default rules.
// It returns a report with the count of findings and a deduplicated list
// of files containing secrets. Actual secret values are never included.
func Scan(dir string) (*model.SecretsReport, error) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}

	src := &sources.Files{
		Path:   dir,
		Sema:   detector.Sema,
		Config: &detector.Config,
	}

	findings, err := detector.DetectSource(context.Background(), src)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, f := range findings {
		rel, err := filepath.Rel(dir, f.File)
		if err != nil {
			rel = f.File
		}
		seen[rel] = true
	}

	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	sort.Strings(files)

	return &model.SecretsReport{
		FindingsCount:    len(findings),
		FilesWithSecrets: files,
	}, nil
}
