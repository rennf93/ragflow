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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"ragflow/internal/entity"
	"ragflow/internal/ingestion/testutil"
)

type recordingApplier struct{ applied []Settings }

func (r *recordingApplier) Apply(s Settings) error {
	r.applied = append(r.applied, s)
	return nil
}

func useSettingsDB(t *testing.T) {
	t.Helper()
	db := testutil.SetupTestDB(t, &entity.SystemSettings{})
	t.Cleanup(testutil.ReplaceDBForTest(t, db))
}

func adminRouter(applier Applier) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := AdminHandlers{Applier: applier}
	r := gin.New()
	r.GET("/guard/settings", h.Get)
	r.PUT("/guard/settings", h.Put)
	return r
}

func put(r http.Handler, body string) (int, map[string]interface{}) {
	req := httptest.NewRequest("PUT", "/guard/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestPutRefusesInvalidSettingsWithAllErrors(t *testing.T) {
	useSettingsDB(t)
	r := adminRouter(nil)
	_, out := put(r, `{"enabled":true,"rate_limit":5,"rate_limit_window":0,"ip_blocklist":["nope"]}`)
	if out["code"] == float64(0) {
		t.Fatalf("invalid settings accepted: %v", out)
	}
	data, _ := out["data"].(map[string]interface{})
	if errs, _ := data["errors"].([]interface{}); len(errs) != 2 {
		t.Fatalf("errors = %v, want 2", data)
	}
	if s, err := LoadSettings(context.Background()); err != nil || s.Version != 0 {
		t.Fatalf("invalid PUT stored something: %+v %v", s, err)
	}
}

func TestPutIncrementsVersionAndAppliesToTheAdminGuard(t *testing.T) {
	useSettingsDB(t)
	applier := &recordingApplier{}
	r := adminRouter(applier)
	for want := int64(1); want <= 2; want++ {
		_, out := put(r, `{"version":99,"enabled":true,"rate_limit":10,"rate_limit_window":60,"ip_allowlist":["10.0.0.0/8"]}`)
		if out["code"] != float64(0) {
			t.Fatalf("valid PUT refused: %v", out)
		}
		s, err := LoadSettings(context.Background())
		if err != nil || s.Version != want || !s.Enabled || s.RateLimit != 10 {
			t.Fatalf("stored = %+v %v, want version %d", s, err, want)
		}
	}
	if len(applier.applied) != 2 || applier.applied[1].Version != 2 {
		t.Fatalf("admin guard applier got %+v", applier.applied)
	}
	req := httptest.NewRequest("GET", "/guard/settings", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"version":2`) {
		t.Fatalf("GET: %s", w.Body.String())
	}
}

func TestHeartbeatResponseCarriesStoredSettings(t *testing.T) {
	useSettingsDB(t)
	if _, _, err := ReplaceSettings(context.Background(), Settings{Enabled: true, RateLimit: 7, RateLimitWindow: 1}); err != nil {
		t.Fatal(err)
	}
	data := AddSettingsToHeartbeat(context.Background(), map[string]interface{}{})
	got, ok := data["guard"].(Settings)
	if !ok || got.Version != 1 || got.RateLimit != 7 {
		t.Fatalf("heartbeat data = %#v", data)
	}
}

func TestHeartbeatGuardKeyReachesApply(t *testing.T) {
	applier := &recordingApplier{}
	response := map[string]interface{}{"guard": map[string]interface{}{
		"version": float64(3), "enabled": true, "rate_limit": float64(9), "rate_limit_window": float64(60),
		"ip_blocklist": []interface{}{"192.0.2.1"},
	}}
	ApplyFromHeartbeat(applier, response)
	if len(applier.applied) != 1 {
		t.Fatalf("applied = %+v", applier.applied)
	}
	if got := applier.applied[0]; got.Version != 3 || !got.Enabled || got.RateLimit != 9 || got.IPBlocklist[0] != "192.0.2.1" {
		t.Fatalf("decoded settings = %+v", got)
	}
}

func TestHeartbeatWithoutGuardKeyChangesNothing(t *testing.T) {
	applier := &recordingApplier{}
	ApplyFromHeartbeat(applier, map[string]interface{}{"other": 1})
	ApplyFromHeartbeat(applier, nil)
	if len(applier.applied) != 0 {
		t.Fatalf("applied = %+v", applier.applied)
	}
}
