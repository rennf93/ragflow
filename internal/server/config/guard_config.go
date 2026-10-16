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

package config

import "github.com/spf13/viper"

// GuardConfig configures the optional request guard (per-IP rate limiting, IP
// allow/block lists and path/query/header screening) of the API and admin
// servers. It is off by default: when Enabled is false no middleware is
// registered.
type GuardConfig struct {
	Enabled bool
	// RateLimit is the maximum requests per RateLimitWindow seconds from one
	// client address. Zero disables rate limiting.
	RateLimit       int
	RateLimitWindow int
	// IPAllowlist, when non-empty, rejects every client address not listed.
	// IPBlocklist rejects the listed addresses. Entries are IPs or CIDRs.
	IPAllowlist []string
	IPBlocklist []string
	// ScreenRequests enables attack-pattern screening of the URL path, query
	// string and headers. Request bodies are never scanned.
	ScreenRequests bool
	// ScreenExcludedParams names query parameters that carry free text and are
	// skipped by the screening.
	ScreenExcludedParams []string
	// UseKvrocks keeps the counters in the configured Kvrocks instance so that
	// several replicas share them. Off keeps them in process memory.
	UseKvrocks bool
}

const (
	defaultGuardRateLimit       = 600
	defaultGuardRateLimitWindow = 60
)

func (c *Config) parseGuardConfig(v *viper.Viper) {
	// Full dotted keys from the root viper, like trusted_proxies, so the YAML
	// file and the RAGFLOW_API_GUARD_* environment layer both apply.
	guard := GuardConfig{
		RateLimit:       defaultGuardRateLimit,
		RateLimitWindow: defaultGuardRateLimitWindow,
	}
	if v.IsSet("api.guard.enabled") {
		guard.Enabled = v.GetBool("api.guard.enabled")
	}
	if v.IsSet("api.guard.rate_limit") {
		guard.RateLimit = v.GetInt("api.guard.rate_limit")
	}
	if v.IsSet("api.guard.rate_limit_window") {
		guard.RateLimitWindow = v.GetInt("api.guard.rate_limit_window")
	}
	if v.IsSet("api.guard.ip_allowlist") {
		guard.IPAllowlist = v.GetStringSlice("api.guard.ip_allowlist")
	}
	if v.IsSet("api.guard.ip_blocklist") {
		guard.IPBlocklist = v.GetStringSlice("api.guard.ip_blocklist")
	}
	if v.IsSet("api.guard.screen_requests") {
		guard.ScreenRequests = v.GetBool("api.guard.screen_requests")
	}
	if v.IsSet("api.guard.screen_excluded_params") {
		guard.ScreenExcludedParams = v.GetStringSlice("api.guard.screen_excluded_params")
	}
	if v.IsSet("api.guard.use_kvrocks") {
		guard.UseKvrocks = v.GetBool("api.guard.use_kvrocks")
	}
	c.apiServer.Guard = guard
}
