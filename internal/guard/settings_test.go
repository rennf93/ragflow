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

import "testing"

func TestValidateSettings(t *testing.T) {
	tests := []struct {
		name     string
		settings Settings
		wantErrs int
	}{
		{"valid", Settings{RateLimit: 10, RateLimitWindow: 60, IPAllowlist: []string{"10.0.0.0/8", "2001:db8::1"}}, 0},
		{"bad cidr", Settings{IPBlocklist: []string{"10.0.0.0/33"}}, 1},
		{"bad ip", Settings{IPAllowlist: []string{"not-an-ip"}}, 1},
		{"window zero with a limit", Settings{RateLimit: 5, RateLimitWindow: 0}, 1},
		{"window zero without a limit", Settings{RateLimit: 0, RateLimitWindow: 0}, 0},
		{"all errors together", Settings{RateLimit: 5, IPAllowlist: []string{"x"}, IPBlocklist: []string{"10.0.0.0/99", "1.2.3.4"}}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.settings.Validate(); len(got) != tt.wantErrs {
				t.Fatalf("Validate() = %v, want %d errors", got, tt.wantErrs)
			}
		})
	}
}
