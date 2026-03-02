package sbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScan_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	report, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.TotalDeps != 0 {
		t.Errorf("expected 0 deps, got %d", report.TotalDeps)
	}
}

func TestScan_GoModule(t *testing.T) {
	dir := t.TempDir()

	goMod := `module example.com/test

go 1.21

require (
	github.com/spf13/cobra v1.8.0
	github.com/spf13/pflag v1.0.5
)
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	goSum := `github.com/cpuguy83/go-md2man/v2 v2.0.3/go.mod h1:tgQtvFlXSQOSOSIRvRPT7W67SCa46tRHOmNcaadrF8o=
github.com/inconshreveable/mousetrap v1.1.0/go.mod h1:vpF70FUmC8bwa3OWnCshd2FqLfsEA9PFc4w1p2J65bw=
github.com/russross/blackfriday/v2 v2.1.0/go.mod h1:+Rmxgy9KzJVeS9/2gXHxylqXiyQDYRxCVz55jGbOGsM=
github.com/spf13/cobra v1.8.0 h1:7aJaZx1B85qltLMc546zn58BxxfZdR/W22ej9CFoEf0=
github.com/spf13/cobra v1.8.0/go.mod h1:WnodtKOvamDL/PwE2M4iKs8aMDBZ5Q5klgD3qfVJQMI=
github.com/spf13/pflag v1.0.5 h1:iy+VFUOCP1a+8yFto/drg2CJ5u0yRoB7fZw3DKv/JXA=
github.com/spf13/pflag v1.0.5/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Gy0=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
`
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.TotalDeps < 2 {
		t.Errorf("expected at least 2 deps, got %d", report.TotalDeps)
	}

	found := false
	for _, eco := range report.Ecosystems {
		if eco.Ecosystem == "go-module" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected go-module ecosystem, got %v", report.Ecosystems)
	}
}

func TestScan_NpmPackage(t *testing.T) {
	dir := t.TempDir()

	packageJSON := `{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21"
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// syft requires a package-lock.json to enumerate individual npm dependencies
	packageLock := `{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0",
      "dependencies": {
        "express": "4.18.2",
        "lodash": "4.17.21"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMg=="
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(packageLock), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.TotalDeps < 2 {
		t.Errorf("expected at least 2 deps, got %d", report.TotalDeps)
	}

	found := false
	for _, eco := range report.Ecosystems {
		if eco.Ecosystem == "npm" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected npm ecosystem, got %v", report.Ecosystems)
	}
}
