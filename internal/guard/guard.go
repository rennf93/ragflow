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

// Package guard wires the optional gin-guard request guard into the Go API and
// admin servers.
package guard

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"

	"github.com/gin-gonic/gin"
	guardgin "github.com/rennf93/gin-guard"
	"github.com/rennf93/guard-core-go/v4/guardcore"
	"go.uber.org/zap"

	"ragflow/internal/common"
	"ragflow/internal/server/config"
)

// healthPaths skip the guard entirely so probes are never limited or blocked.
// The engine's own exclude_paths would not do: it still enforces the rate limit
// and the IP lists on excluded paths.
var healthPaths = map[string]bool{"/health": true, "/api/v1/system/ping": true, "/api/v1/system/healthz": true}

// New builds one guard from s. trustedProxies is the list the server already
// hands to common.ConfigureTrustedProxies (nil means the loopback default), so
// the guard resolves the client address from X-Forwarded-For exactly as
// c.ClientIP() does. The returned func releases the engine.
func New(s Settings, trustedProxies []string, kvrocks config.KvrocksConfig) (gin.HandlerFunc, func(), error) {
	if trustedProxies == nil {
		trustedProxies = common.DefaultTrustedProxies
	}
	secCfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.TrustedProxies = trustedProxies
		c.EnableRedis = false
		c.RedisURL = kvrocksURL(kvrocks)
		c.RedisPrefix = "ragflow:guard:"
		// A shared-state outage must not take the API down.
		c.RedisFailOpen = true
		c.EnableRateLimiting = s.RateLimit > 0
		if s.RateLimit > 0 {
			c.RateLimit = s.RateLimit
			c.RateLimitWindow = s.RateLimitWindow
		}
		c.Whitelist = s.IPAllowlist
		c.Blacklist = s.IPBlocklist
		c.EnableIPBanning = false
		c.EnablePenetrationDetection = s.ScreenRequests
		c.EnabledDetectionCategories = detectionCategoriesWithoutSSRF()
		// Chat messages, prompts and documents are free text: never scan bodies.
		noBody := false
		c.DetectionScanBody = &noBody
		c.ExcludedDetectionParams = toSet(s.ScreenExcludedParams)
		c.ExcludedDetectionHeaders = map[string]bool{"authorization": true, "cookie": true}
		c.ExcludePaths = nil
		// No extra response headers: the web app and embeds keep their own.
		c.SecurityHeaders = nil
		c.OnBlock = func(_ guardcore.Request, p map[string]any) {
			common.Warn("request guard blocked a request",
				zap.Any("method", p["method"]), zap.Any("path", p["path"]),
				zap.Any("client_ip", p["client_ip"]), zap.Any("check", p["check_name"]),
				zap.Any("reason", p["reason"]))
		}
	})
	if err != nil {
		return nil, nil, fmt.Errorf("request guard config: %w", err)
	}
	engine, err := guardcore.NewEngine(secCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("request guard engine: %w", err)
	}
	if err := engine.Initialize(); err != nil {
		return nil, nil, fmt.Errorf("request guard init: %w", err)
	}
	mw, err := guardgin.New(engine)
	if err != nil {
		return nil, nil, err
	}
	return mw, func() { _ = engine.Close() }, nil
}

// guard-core-go v4.4.1 flags a Referer on localhost or a LAN address as ssrf.
func detectionCategoriesWithoutSSRF() []string {
	return slices.DeleteFunc(slices.Clone(guardcore.AllDetectionCategories), func(c string) bool { return c == "ssrf" })
}

func toSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

func kvrocksURL(k config.KvrocksConfig) string {
	u := url.URL{Scheme: "redis", Host: net.JoinHostPort(k.Host, strconv.Itoa(k.Port)), Path: "/" + strconv.Itoa(k.DB)}
	if k.Password != "" || k.Username != "" {
		u.User = url.UserPassword(k.Username, k.Password)
	}
	return u.String()
}
