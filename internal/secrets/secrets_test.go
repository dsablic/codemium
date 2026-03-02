package secrets_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/dsablic/codemium/internal/secrets"
)

func TestScan_NoSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644)

	report, err := secrets.Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if report.FindingsCount != 0 {
		t.Errorf("expected 0 findings, got %d", report.FindingsCount)
	}
	if len(report.FilesWithSecrets) != 0 {
		t.Errorf("expected no files, got %v", report.FilesWithSecrets)
	}
}

func TestScan_WithSecrets(t *testing.T) {
	dir := t.TempDir()

	// Write a file containing a fake private key (gitleaks default rules detect this)
	content := `package main

var privateKey = ` + "`" + `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hgdFaIkmJJMPDa
rKIgJGiDGfnsTyzuFxkDJTKM1FHhck9tiBJKlCLMUPFWUDAzVIhG23+5ybCnWASB
RWFnmFSVNSBcg3nP5UITnZ1hN4rik3X3VrzCzknUFqbWJNPa7e6DPFZ0bBJ2MJfP
VFF7FiGBPKrlKJHSKaGA3MgE3z5Pz3MC+WbDIkINK1SF8QQXV4XN3yjCdFWdYnCd
a8fN+3R8J0qYnBb9O5JA0st6OH8SkXWLKH5kiD4qMHr2FW97cBVMPOdkLSUSPCxQ
WzcJjCpniYK5z5gQR1QRB6e+bn+w54sN8b5T7wIDAQABAoIBAC5RgZ+hBx7xHNaM
pPgwGMnCd6GJsBnEaUkMRFJTakVGpLJm9N2IRe9QLAK7jEiGCcSKjC4JKB3VlKvN
-----END RSA PRIVATE KEY-----` + "`" + `
`
	os.WriteFile(filepath.Join(dir, "config.go"), []byte(content), 0o644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644)

	report, err := secrets.Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if report.FindingsCount == 0 {
		t.Error("expected findings, got 0")
	}

	if len(report.FilesWithSecrets) == 0 {
		t.Error("expected files with secrets")
	}

	// Should contain config.go
	sort.Strings(report.FilesWithSecrets)
	found := false
	for _, f := range report.FilesWithSecrets {
		if f == "config.go" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected config.go in files, got %v", report.FilesWithSecrets)
	}
}

func TestScan_DeduplicatesFiles(t *testing.T) {
	dir := t.TempDir()

	// Multiple secrets in the same file: a private key and a password assignment
	content := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hgdFaIkmJJMPDa
rKIgJGiDGfnsTyzuFxkDJTKM1FHhck9tiBJKlCLMUPFWUDAzVIhG23+5ybCnWASB
RWFnmFSVNSBcg3nP5UITnZ1hN4rik3X3VrzCzknUFqbWJNPa7e6DPFZ0bBJ2MJfP
VFF7FiGBPKrlKJHSKaGA3MgE3z5Pz3MC+WbDIkINK1SF8QQXV4XN3yjCdFWdYnCd
a8fN+3R8J0qYnBb9O5JA0st6OH8SkXWLKH5kiD4qMHr2FW97cBVMPOdkLSUSPCxQ
WzcJjCpniYK5z5gQR1QRB6e+bn+w54sN8b5T7wIDAQABAoIBAC5RgZ+hBx7xHNaM
pPgwGMnCd6GJsBnEaUkMRFJTakVGpLJm9N2IRe9QLAK7jEiGCcSKjC4JKB3VlKvN
-----END RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk/DPKEk5Yj0zuqoAcGBSuBBAAi
oWQDYgAEY1GlPyRPrzIhfA8PWEgRkBNlwV3OSBK4FHOY9FIwdAkPxlREpTDNOFn5
gLPKOMN/LetFXoXT5EEbFkOzQcL1jwPH3MjmjSz1t2fBPQNxPxmhE+XAmmw3gLhH
-----END EC PRIVATE KEY-----
`
	os.WriteFile(filepath.Join(dir, "env.txt"), []byte(content), 0o644)

	report, err := secrets.Scan(dir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if report.FindingsCount < 2 {
		t.Errorf("expected multiple findings, got %d", report.FindingsCount)
	}

	fileCount := 0
	for _, f := range report.FilesWithSecrets {
		if f == "env.txt" {
			fileCount++
		}
	}
	if fileCount != 1 {
		t.Errorf("expected env.txt once, appeared %d times", fileCount)
	}
}
