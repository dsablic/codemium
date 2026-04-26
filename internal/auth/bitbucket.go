// internal/auth/bitbucket.go
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	bitbucketAuthorizeURL = "https://bitbucket.org/site/oauth2/authorize"
	bitbucketTokenURL     = "https://bitbucket.org/site/oauth2/access_token"
)

type BitbucketOAuth struct {
	ClientID     string
	ClientSecret string
	TokenURL     string // overridable for testing
}

func (b *BitbucketOAuth) tokenURL() string {
	if b.TokenURL != "" {
		return b.TokenURL
	}
	return bitbucketTokenURL
}

func (b *BitbucketOAuth) Login(ctx context.Context) (Credentials, error) {
	callbackPort, err := findFreePort()
	if err != nil {
		return Credentials{}, fmt.Errorf("find free port: %w", err)
	}
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", callbackPort)

	// Generate a random state parameter for CSRF protection
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return Credentials{}, fmt.Errorf("generate state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			errCh <- fmt.Errorf("state mismatch in OAuth callback (possible CSRF)")
			fmt.Fprintln(w, "Error: state mismatch.")
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no code in callback")
			fmt.Fprintln(w, "Error: no authorization code received.")
			return
		}
		codeCh <- code
		fmt.Fprintln(w, "Authorization successful! You can close this tab.")
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", callbackPort),
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer server.Shutdown(ctx)

	authURL := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&state=%s",
		bitbucketAuthorizeURL,
		url.QueryEscape(b.ClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(state),
	)
	openBrowser(authURL)

	select {
	case code := <-codeCh:
		return b.ExchangeCode(ctx, code)
	case err := <-errCh:
		return Credentials{}, err
	case <-ctx.Done():
		return Credentials{}, ctx.Err()
	}
}

func (b *BitbucketOAuth) ExchangeCode(ctx context.Context, code string) (Credentials, error) {
	return b.tokenRequest(ctx, url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	})
}

func (b *BitbucketOAuth) RefreshToken(ctx context.Context, refreshToken string) (Credentials, error) {
	return b.tokenRequest(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func (b *BitbucketOAuth) tokenRequest(ctx context.Context, form url.Values) (Credentials, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return Credentials{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(b.ClientID, b.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Credentials{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Credentials{}, fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return Credentials{}, fmt.Errorf("decode token response: %w", err)
	}

	return Credentials{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}, nil
}

func findFreePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	if cmd != nil {
		cmd.Start()
	}
}
