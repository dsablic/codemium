package provider

import (
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const defaultMaxRetries = 5

// RateLimitTransport wraps an http.RoundTripper with rate limiting and 429 retry.
type RateLimitTransport struct {
	ReqPerSec float64           // 0 = unlimited (retry-only)
	Base      http.RoundTripper // nil = http.DefaultTransport

	once    sync.Once
	limiter chan struct{}
	done    chan struct{} // closed to stop the ticker goroutine
}

func (t *RateLimitTransport) init() {
	t.done = make(chan struct{})
	if t.ReqPerSec > 0 {
		t.limiter = make(chan struct{}, 1)
		interval := time.Duration(float64(time.Second) / t.ReqPerSec)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					select {
					case t.limiter <- struct{}{}:
					default:
					}
				case <-t.done:
					return
				}
			}
		}()
	}
}

// Close stops the rate limiter's background goroutine.
// It is safe to call multiple times.
func (t *RateLimitTransport) Close() {
	t.once.Do(t.init) // ensure done channel exists
	select {
	case <-t.done:
		// already closed
	default:
		close(t.done)
	}
}

func (t *RateLimitTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// RoundTrip implements http.RoundTripper with rate limiting and 429 retry.
func (t *RateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.once.Do(t.init)

	for attempt := 0; ; attempt++ {
		// Wait for rate limiter token if configured
		if t.limiter != nil {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-t.limiter:
			}
		}

		resp, err := t.base().RoundTrip(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusTooManyRequests || attempt >= defaultMaxRetries {
			return resp, nil
		}

		// Drain and close body before retry
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// Backoff: use Retry-After header or exponential (1s, 2s, 4s...)
		delay := time.Duration(1<<uint(attempt)) * time.Second
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
				delay = time.Duration(secs) * time.Second
			}
		}

		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
		}
	}
}
