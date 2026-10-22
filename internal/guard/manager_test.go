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
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"ragflow/internal/server/config"
)

type closeLog struct {
	mu     sync.Mutex
	closed []int
}

func (l *closeLog) record(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = append(l.closed, n)
}

func (l *closeLog) snapshot() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]int(nil), l.closed...)
}

func newManagerRouter(t *testing.T) (*Manager, *gin.Engine, *closeLog) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	log := &closeLog{}
	m := NewManager(nil, config.KvrocksConfig{})
	built := 0
	m.build = func(s Settings, proxies []string, k config.KvrocksConfig) (gin.HandlerFunc, func(), error) {
		mw, closeFn, err := New(s, proxies, k)
		if err != nil {
			return nil, nil, err
		}
		built++
		n := built
		return mw, func() { closeFn(); log.record(n) }, nil
	}
	r := gin.New()
	r.Use(m.Middleware())
	r.GET("/ok", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/health", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/search", func(c *gin.Context) { c.String(200, "ok") })
	return m, r, log
}

func TestPassThroughUntilFirstSettings(t *testing.T) {
	_, r, _ := newManagerRouter(t)
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != 200 {
		t.Fatalf("no settings yet: got %d", w.Code)
	}
}

func TestSwapChangesBlocking(t *testing.T) {
	m, r, log := newManagerRouter(t)
	if err := m.Apply(Settings{Version: 1, Enabled: true, IPBlocklist: []string{"198.51.100.7"}}); err != nil {
		t.Fatal(err)
	}
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("v1: got %d, want 403", w.Code)
	}
	if err := m.Apply(Settings{Version: 2, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != 200 {
		t.Fatalf("v2: got %d, want 200", w.Code)
	}
	if got := log.snapshot(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("closed engines = %v, want [1]", got)
	}
}

func TestOlderVersionIsIgnored(t *testing.T) {
	m, r, _ := newManagerRouter(t)
	_ = m.Apply(Settings{Version: 5, Enabled: true, IPBlocklist: []string{"198.51.100.7"}})
	_ = m.Apply(Settings{Version: 5, Enabled: true})
	_ = m.Apply(Settings{Version: 4, Enabled: true})
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("older or equal version replaced the guard: got %d", w.Code)
	}
}

func TestDisabledPassesThrough(t *testing.T) {
	m, r, log := newManagerRouter(t)
	_ = m.Apply(Settings{Version: 1, Enabled: true, IPBlocklist: []string{"198.51.100.7"}})
	if err := m.Apply(Settings{Version: 2, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != 200 {
		t.Fatalf("disabled: got %d, want 200", w.Code)
	}
	if got := log.snapshot(); len(got) != 1 {
		t.Fatalf("closed engines = %v, want one", got)
	}
}

func TestInvalidSettingsKeepCurrentGuard(t *testing.T) {
	m, r, _ := newManagerRouter(t)
	_ = m.Apply(Settings{Version: 1, Enabled: true, IPBlocklist: []string{"198.51.100.7"}})
	if err := m.Apply(Settings{Version: 2, Enabled: true, IPBlocklist: []string{"bogus"}}); err == nil {
		t.Fatal("invalid settings must return an error")
	}
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("invalid settings replaced the guard: got %d", w.Code)
	}
	// The version did not advance, so a valid version 2 still applies.
	if err := m.Apply(Settings{Version: 2, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != 200 {
		t.Fatalf("valid v2 after a rejected v2: got %d", w.Code)
	}
}

func TestInFlightRequestFinishesOnOldGuardBeforeItsEngineCloses(t *testing.T) {
	m, r, log := newManagerRouter(t)
	_ = m.Apply(Settings{Version: 1, Enabled: true, RateLimit: 100, RateLimitWindow: 60})
	entered := make(chan struct{})
	release := make(chan struct{})
	r.GET("/slow", func(c *gin.Context) {
		close(entered)
		<-release
		c.String(200, "done")
	})
	done := make(chan int, 1)
	go func() { done <- do(r, "GET", "/slow", "198.51.100.7", "", nil).Code }()
	<-entered
	if err := m.Apply(Settings{Version: 2, Enabled: true, RateLimit: 100, RateLimitWindow: 60}); err != nil {
		t.Fatal(err)
	}
	if got := log.snapshot(); len(got) != 0 {
		t.Fatalf("v1 engine closed while a request was in flight: %v", got)
	}
	close(release)
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("in-flight request: got %d, want 200", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not finish")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(log.snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := log.snapshot(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("closed engines = %v, want [1] after the request finished", got)
	}
}

func TestRateLimitResetsOnSwap(t *testing.T) {
	m, r, _ := newManagerRouter(t)
	_ = m.Apply(Settings{Version: 1, Enabled: true, RateLimit: 3, RateLimitWindow: 60})
	for i := 0; i < 3; i++ {
		if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: got %d, want 429", w.Code)
	}
	_ = m.Apply(Settings{Version: 2, Enabled: true, RateLimit: 100, RateLimitWindow: 60})
	if w := do(r, "GET", "/ok", "198.51.100.7", "", nil); w.Code != 200 {
		t.Fatalf("after v2: got %d, want 200", w.Code)
	}
}

func TestScreeningSkipsSSRFCategory(t *testing.T) {
	m, r, _ := newManagerRouter(t)
	_ = m.Apply(Settings{Version: 1, Enabled: true, ScreenRequests: true})
	req := httptest.NewRequest("GET", "/ok", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	req.Header.Set("Referer", "http://localhost:9222/")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("localhost Referer: got %d, want 200", w.Code)
	}
	if w := do(r, "GET", "/search?q="+url.QueryEscape("<script>alert(1)</script>"), "198.51.100.8", "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("xss in query: got %d, want 400", w.Code)
	}
}

func TestHealthPathsSkipTheManagedGuard(t *testing.T) {
	m, r, _ := newManagerRouter(t)
	_ = m.Apply(Settings{Version: 1, Enabled: true, RateLimit: 1, RateLimitWindow: 60})
	for i := 0; i < 5; i++ {
		if w := do(r, "GET", "/health", "198.51.100.7", "", nil); w.Code != 200 {
			t.Fatalf("health: %d", w.Code)
		}
	}
}
