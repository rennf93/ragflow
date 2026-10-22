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
	"fmt"
	"net"
	"net/netip"
)

// Settings is the guard configuration the Admin service stores and delivers to
// the API and admin servers. A higher Version replaces a lower one.
type Settings struct {
	Version              int64    `json:"version"`
	Enabled              bool     `json:"enabled"`
	RateLimit            int      `json:"rate_limit"`
	RateLimitWindow      int      `json:"rate_limit_window"`
	IPAllowlist          []string `json:"ip_allowlist"`
	IPBlocklist          []string `json:"ip_blocklist"`
	ScreenRequests       bool     `json:"screen_requests"`
	ScreenExcludedParams []string `json:"screen_excluded_params"`
}

// Validate returns every problem found, not only the first.
func (s Settings) Validate() []error {
	var errs []error
	if s.RateLimit < 0 {
		errs = append(errs, fmt.Errorf("rate_limit must not be negative, got %d", s.RateLimit))
	}
	if s.RateLimit > 0 && s.RateLimitWindow < 1 {
		errs = append(errs, fmt.Errorf("rate_limit_window must be at least 1 when rate_limit is above 0, got %d", s.RateLimitWindow))
	}
	errs = appendInvalidEntries(errs, "ip_allowlist", s.IPAllowlist)
	return appendInvalidEntries(errs, "ip_blocklist", s.IPBlocklist)
}

func appendInvalidEntries(errs []error, field string, entries []string) []error {
	for _, entry := range entries {
		if _, _, err := net.ParseCIDR(entry); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(entry); err == nil {
			continue
		}
		errs = append(errs, fmt.Errorf("%s: %q is not an IP address or CIDR", field, entry))
	}
	return errs
}
