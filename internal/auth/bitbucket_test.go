// internal/auth/bitbucket_test.go
package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dsablic/codemium/internal/auth"
)

func TestBitbucketTokenExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("expected grant_type=authorization_code, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "test-code" {
			t.Errorf("expected code=test-code, got %s", r.Form.Get("code"))
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "bb-access-token",
			"refresh_token": "bb-refresh-token",
			"expires_in":    3600,
			"token_type":    "bearer",
		})
	}))
	defer server.Close()

	bb := auth.BitbucketOAuth{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		TokenURL:     server.URL,
	}

	cred, err := bb.ExchangeCode(context.Background(), "test-code")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if cred.AccessToken != "bb-access-token" {
		t.Errorf("expected bb-access-token, got %s", cred.AccessToken)
	}
	if cred.RefreshToken != "bb-refresh-token" {
		t.Errorf("expected bb-refresh-token, got %s", cred.RefreshToken)
	}
}

func TestBitbucketTokenRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected grant_type=refresh_token, got %s", r.Form.Get("grant_type"))
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access-token",
			"refresh_token": "new-refresh-token",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	bb := auth.BitbucketOAuth{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		TokenURL:     server.URL,
	}

	cred, err := bb.RefreshToken(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if cred.AccessToken != "new-access-token" {
		t.Errorf("expected new-access-token, got %s", cred.AccessToken)
	}
}
