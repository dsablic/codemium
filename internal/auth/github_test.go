// internal/auth/github_test.go
package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/labtiva/codemium/internal/auth"
)

func TestGitHubDeviceFlow(t *testing.T) {
	var pollCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "test-device-code",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://github.com/login/device",
				"expires_in":       900,
				"interval":         1,
			})
		case "/login/oauth/access_token":
			count := pollCount.Add(1)
			if count < 2 {
				json.NewEncoder(w).Encode(map[string]any{
					"error": "authorization_pending",
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "gh-access-token",
				"token_type":   "bearer",
				"scope":        "repo,read:org",
			})
		}
	}))
	defer server.Close()

	gh := auth.GitHubOAuth{
		ClientID:    "test-client-id",
		DeviceURL:   server.URL + "/login/device/code",
		TokenURL:    server.URL + "/login/oauth/access_token",
		OpenBrowser: false,
	}

	cred, err := gh.Login(context.Background())
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if cred.AccessToken != "gh-access-token" {
		t.Errorf("expected gh-access-token, got %s", cred.AccessToken)
	}
}
