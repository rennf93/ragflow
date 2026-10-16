//
//  Copyright 2026 The InfiniFlow Authors. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

package guard

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"ragflow/internal/common"
	"ragflow/internal/server/config"
)

// newRouter mirrors the order used by the servers: trusted proxies, Recovery,
// then the guard. A CORS-style middleware registered before the guard stands in
// for any header middleware that must also decorate blocked responses.
func newRouter(t *testing.T, cfg config.GuardConfig, proxies []string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := common.ConfigureTrustedProxies(r, proxies); err != nil {
		t.Fatal(err)
	}
	r.Use(gin.Recovery())
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Next()
	})
	cfg.Enabled = true
	mw, closeGuard, err := New(cfg, proxies, config.KvrocksConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeGuard)
	r.Use(mw)
	r.GET("/ok", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/health", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/search", func(c *gin.Context) { c.String(200, "ok") })
	r.POST("/chat", func(c *gin.Context) {
		n, _ := io.Copy(io.Discard, c.Request.Body)
		c.JSON(200, gin.H{"bytes": n})
	})
	return r
}

func do(r http.Handler, method, target, remote, xff string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = remote + ":1234"
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestDisabledRegistersNothing(t *testing.T) {
	mw, closeGuard, err := New(config.GuardConfig{RateLimit: 1, RateLimitWindow: 60}, nil, config.KvrocksConfig{})
	if err != nil || mw != nil || closeGuard != nil {
		t.Fatalf("disabled guard must return nil, nil, nil, got %v %v %v", mw != nil, closeGuard != nil, err)
	}
}

func TestRateLimitBurstReturns429WithCORSHeader(t *testing.T) {
	r := newRouter(t, config.GuardConfig{RateLimit: 3, RateLimitWindow: 60}, nil)
	for i := 0; i < 3; i++ {
		if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := do(r, "GET", "/ok", "198.51.100.7", "", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("burst: got %d, want 429", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("429 lost the CORS header set by the outer middleware")
	}
	if w := do(r, "GET", "/ok", "198.51.100.8", "", nil); w.Code != 200 {
		t.Fatalf("another client must not be limited: %d", w.Code)
	}
	for i := 0; i < 10; i++ {
		if w := do(r, "GET", "/health", "198.51.100.7", "", nil); w.Code != 200 {
			t.Fatalf("health must stay outside the guard: %d", w.Code)
		}
	}
}

func TestIPAllowlistReturns403WithCORSHeader(t *testing.T) {
	r := newRouter(t, config.GuardConfig{RateLimit: 100, RateLimitWindow: 60, IPAllowlist: []string{"10.0.0.0/8"}}, nil)
	w := do(r, "GET", "/ok", "192.0.2.1", "", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("outside allowlist: got %d, want 403", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("403 lost the CORS header")
	}
	if w := do(r, "GET", "/ok", "10.1.2.3", "", nil); w.Code != 200 {
		t.Fatalf("inside allowlist: got %d", w.Code)
	}
}

func TestSpoofedForwardedForFromUntrustedPeerIsIgnored(t *testing.T) {
	r := newRouter(t, config.GuardConfig{RateLimit: 2, RateLimitWindow: 60, IPAllowlist: []string{"10.0.0.0/8"}}, nil)
	// An untrusted peer naming an allowed address in X-Forwarded-For stays blocked.
	if w := do(r, "GET", "/ok", "192.0.2.9", "10.1.2.3", nil); w.Code != http.StatusForbidden {
		t.Fatalf("spoofed allowlisted address: got %d, want 403", w.Code)
	}
	// The default trusts loopback (the bundled nginx), so its forwarded client is honoured,
	// the same address c.ClientIP() resolves.
	if w := do(r, "GET", "/ok", "127.0.0.1", "10.1.2.3", nil); w.Code != 200 {
		t.Fatalf("loopback proxy with allowed client: got %d", w.Code)
	}
	if w := do(r, "GET", "/ok", "127.0.0.1", "203.0.113.5", nil); w.Code != http.StatusForbidden {
		t.Fatalf("loopback proxy with disallowed client: got %d", w.Code)
	}
}

func TestRotatingForwardedForCannotEvadeRateLimit(t *testing.T) {
	r := newRouter(t, config.GuardConfig{RateLimit: 2, RateLimitWindow: 60}, nil)
	codes := make([]int, 0, 4)
	for _, spoof := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		codes = append(codes, do(r, "GET", "/ok", "192.0.2.9", spoof, nil).Code)
	}
	if codes[2] != http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests {
		t.Fatalf("rotating X-Forwarded-For evaded the limit: %v", codes)
	}
}

func TestAttackInQueryBlockedButBodyAndFreeTextParamsPass(t *testing.T) {
	r := newRouter(t, config.GuardConfig{RateLimit: 100, RateLimitWindow: 60, ScreenRequests: true, ScreenExcludedParams: []string{"keywords"}}, nil)
	attack := "<script>alert(1)</script>"
	if w := do(r, "GET", "/search?q="+url.QueryEscape(attack), "198.51.100.7", "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("query attack: got %d, want 400", w.Code)
	}
	if w := do(r, "GET", "/search?keywords="+url.QueryEscape(attack), "198.51.100.8", "", nil); w.Code != 200 {
		t.Fatalf("excluded param: got %d", w.Code)
	}
	// Bodies are free text and never scanned.
	if w := do(r, "POST", "/chat", "198.51.100.9", "", strings.NewReader(attack)); w.Code != 200 {
		t.Fatalf("body must not be scanned: got %d", w.Code)
	}
}

func TestScreeningOffByDefaultWhenEnabled(t *testing.T) {
	r := newRouter(t, config.GuardConfig{RateLimit: 100, RateLimitWindow: 60}, nil)
	if w := do(r, "GET", "/search?q="+url.QueryEscape("<script>alert(1)</script>"), "198.51.100.7", "", nil); w.Code != 200 {
		t.Fatalf("screening is opt-in: got %d", w.Code)
	}
}

func TestStreamingResponseIsNotBuffered(t *testing.T) {
	r := newRouter(t, config.GuardConfig{RateLimit: 100, RateLimitWindow: 60, ScreenRequests: true}, nil)
	release := make(chan struct{})
	r.GET("/stream", func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		c.Writer.WriteString("data: first\n\n")
		c.Writer.Flush()
		<-release
		c.Writer.WriteString("data: second\n\n")
		c.Writer.Flush()
	})
	srv := httptest.NewServer(r)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		if s != "data: first\n" {
			t.Fatalf("first event: %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first SSE event was held back while the handler was still running")
	}
	close(release)
}

func TestLargeUploadPassesUnbuffered(t *testing.T) {
	r := newRouter(t, config.GuardConfig{RateLimit: 100, RateLimitWindow: 60, ScreenRequests: true}, nil)
	const size = 64 << 20
	w := do(r, "POST", "/chat", "198.51.100.7", "", io.LimitReader(zeroReader{}, size))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "67108864") {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestKvrocksURL(t *testing.T) {
	got := kvrocksURL(config.KvrocksConfig{Host: "::1", Port: 6666, Password: "p w", DB: 2})
	if got != "redis://:p%20w@[::1]:6666/2" {
		t.Fatalf("got %s", got)
	}
}
