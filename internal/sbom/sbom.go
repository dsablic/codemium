package sbom

import (
	"context"
	"sort"

	"github.com/anchore/syft/syft"
	"github.com/dsablic/codemium/internal/model"
	_ "modernc.org/sqlite" // required by syft's RPM cataloger
)

// Scan uses syft to scan the given directory for software dependencies
// and returns a summary report grouped by ecosystem.
func Scan(ctx context.Context, dir string) (*model.SBOMReport, error) {
	src, err := syft.GetSource(ctx, dir, nil)
	if err != nil {
		return &model.SBOMReport{}, nil
	}
	defer src.Close()

	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return &model.SBOMReport{}, nil
	}

	counts := map[string]int{}
	total := 0
	for pkg := range s.Artifacts.Packages.Enumerate() {
		eco := string(pkg.Type)
		counts[eco]++
		total++
	}

	ecosystems := make([]model.EcosystemDeps, 0, len(counts))
	for eco, count := range counts {
		ecosystems = append(ecosystems, model.EcosystemDeps{Ecosystem: eco, Count: count})
	}
	sort.Slice(ecosystems, func(i, j int) bool {
		return ecosystems[i].Count > ecosystems[j].Count
	})

	return &model.SBOMReport{TotalDeps: total, Ecosystems: ecosystems}, nil
}
