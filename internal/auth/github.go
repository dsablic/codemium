// internal/auth/github.go
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	githubDeviceURL = "https://github.com/login/device/code"
	githubTokenURL  = "https://github.com/login/oauth/access_token"
)

type GitHubOAuth struct {
	ClientID    string
	DeviceURL   string // overridable for testing
	TokenURL    string // overridable for testing
	OpenBrowser bool
}

func (g *GitHubOAuth) deviceURL() string {
	if g.DeviceURL != "" {
		return g.DeviceURL
	}
	return githubDeviceURL
}

func (g *GitHubOAuth) tokenURL() string {
	if g.TokenURL != "" {
		return g.TokenURL
	}
	return githubTokenURL
}

func (g *GitHubOAuth) Login(ctx context.Context) (Credentials, error) {
	deviceResp, err := g.requestDeviceCode(ctx)
	if err != nil {
		return Credentials{}, err
	}

	fmt.Printf("\nPlease visit: %s\nand enter the code: %s\n\n", deviceResp.VerificationURI, deviceResp.UserCode)

	if g.OpenBrowser {
		openBrowser(deviceResp.VerificationURI)
	}

	return g.pollForToken(ctx, deviceResp.DeviceCode, time.Duration(deviceResp.Interval)*time.Second)
}

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (g *GitHubOAuth) requestDeviceCode(ctx context.Context) (deviceCodeResponse, error) {
	body := fmt.Sprintf(`{"client_id":"%s","scope":"repo read:org"}`, g.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.deviceURL(), strings.NewReader(body))
	if err != nil {
		return deviceCodeResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return deviceCodeResponse{}, fmt.Errorf("device code request: %w", err)
	}
	defer resp.Body.Close()

	var result deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return deviceCodeResponse{}, fmt.Errorf("decode device code response: %w", err)
	}
	return result, nil
}

func (g *GitHubOAuth) pollForToken(ctx context.Context, deviceCode string, interval time.Duration) (Credentials, error) {
	if interval < time.Second {
		interval = time.Second
	}

	for {
		select {
		case <-ctx.Done():
			return Credentials{}, ctx.Err()
		case <-time.After(interval):
		}

		body := fmt.Sprintf(`{"client_id":"%s","device_code":"%s","grant_type":"urn:ietf:params:oauth:grant-type:device_code"}`, g.ClientID, deviceCode)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL(), strings.NewReader(body))
		if err != nil {
			return Credentials{}, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return Credentials{}, fmt.Errorf("token poll: %w", err)
		}

		var result struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
			Error       string `json:"error"`
			Interval    int    `json:"interval"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		switch result.Error {
		case "":
			if result.AccessToken != "" {
				return Credentials{AccessToken: result.AccessToken}, nil
			}
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "expired_token":
			return Credentials{}, fmt.Errorf("device code expired, please try again")
		case "access_denied":
			return Credentials{}, fmt.Errorf("authorization denied by user")
		default:
			return Credentials{}, fmt.Errorf("unexpected error: %s", result.Error)
		}
	}
}
