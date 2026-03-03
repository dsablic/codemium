// internal/auth/gitlab.go
package auth

import (
	"os/exec"
	"strings"
)

// GlabCLIToken attempts to get a GitLab token from the glab CLI tool.
// Returns the token and true if successful, or empty string and false otherwise.
func GlabCLIToken() (string, bool) {
	// Try "glab auth status -t" first — works with OAuth2 and PAT auth.
	out, err := exec.Command("glab", "auth", "status", "-t").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Token found:") {
				parts := strings.SplitN(line, "Token found:", 2)
				if len(parts) == 2 {
					token := strings.TrimSpace(parts[1])
					if token != "" && !strings.Contains(token, "***") {
						return token, true
					}
				}
			}
		}
	}
	// Fall back to "glab config get token" for older glab versions.
	out, err = exec.Command("glab", "config", "get", "token", "--host", "gitlab.com").Output()
	if err != nil {
		return "", false
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", false
	}
	return token, true
}
