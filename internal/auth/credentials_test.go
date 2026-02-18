// internal/auth/credentials_test.go
package auth_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dsablic/codemium/internal/auth"
)

func TestCredentialsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewFileStore(filepath.Join(dir, "credentials.json"))

	cred := auth.Credentials{
		AccessToken:  "test-token",
		RefreshToken: "test-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	if err := store.Save("bitbucket", cred); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	loaded, err := store.Load("bitbucket")
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if loaded.AccessToken != "test-token" {
		t.Errorf("expected test-token, got %s", loaded.AccessToken)
	}
	if loaded.RefreshToken != "test-refresh" {
		t.Errorf("expected test-refresh, got %s", loaded.RefreshToken)
	}
}

func TestCredentialsMissing(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewFileStore(filepath.Join(dir, "credentials.json"))

	_, err := store.Load("github")
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestCredentialsEnvOverride(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewFileStore(filepath.Join(dir, "credentials.json"))

	t.Setenv("CODEMIUM_BITBUCKET_TOKEN", "env-token")

	cred, err := store.LoadWithEnv("bitbucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.AccessToken != "env-token" {
		t.Errorf("expected env-token, got %s", cred.AccessToken)
	}
}

func TestCredentialsFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	store := auth.NewFileStore(path)

	cred := auth.Credentials{AccessToken: "secret"}
	if err := store.Save("github", cred); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}
}
