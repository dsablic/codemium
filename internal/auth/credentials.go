// internal/auth/credentials.go
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var ErrNoCredentials = errors.New("no credentials found")

type Credentials struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Username     string    `json:"username,omitempty"`
}

func (c Credentials) Expired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

type FileStore struct {
	path string
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func DefaultStorePath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(configDir, "codemium", "credentials.json")
}

func (s *FileStore) Save(provider string, cred Credentials) error {
	all, _ := s.loadAll()
	if all == nil {
		all = make(map[string]Credentials)
	}
	all[provider] = cred

	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

func (s *FileStore) Load(provider string) (Credentials, error) {
	all, err := s.loadAll()
	if err != nil {
		return Credentials{}, ErrNoCredentials
	}
	cred, ok := all[provider]
	if !ok {
		return Credentials{}, ErrNoCredentials
	}
	return cred, nil
}

func (s *FileStore) LoadWithEnv(provider string) (Credentials, error) {
	envKey := fmt.Sprintf("CODEMIUM_%s_TOKEN", toUpperSnake(provider))
	if token := os.Getenv(envKey); token != "" {
		cred := Credentials{AccessToken: token}
		userKey := fmt.Sprintf("CODEMIUM_%s_USERNAME", toUpperSnake(provider))
		cred.Username = os.Getenv(userKey)
		return cred, nil
	}
	return s.Load(provider)
}

func (s *FileStore) loadAll() (map[string]Credentials, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var all map[string]Credentials
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	return all, nil
}

func toUpperSnake(s string) string {
	result := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result = append(result, c)
	}
	return string(result)
}
