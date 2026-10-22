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

package admin

import (
	"context"
	"testing"
	"time"

	"ragflow/internal/common"
	"ragflow/internal/entity"
	"ragflow/internal/guard"
	"ragflow/internal/ingestion/testutil"
)

func TestHandleHeartbeatCarriesStoredGuardSettings(t *testing.T) {
	db := testutil.SetupTestDB(t, &entity.SystemSettings{})
	t.Cleanup(testutil.ReplaceDBForTest(t, db))
	if _, _, err := guard.ReplaceSettings(context.Background(), guard.Settings{Enabled: true, RateLimit: 4, RateLimitWindow: 30}); err != nil {
		t.Fatal(err)
	}

	code, data, _ := NewService().HandleHeartbeat(&common.BaseMessage{
		ServerName: "api-1", ServerType: common.ServerType("api"), Host: "127.0.0.1", Port: 9380, Timestamp: time.Now(),
	})
	if code != common.CodeLicenseValid {
		t.Fatalf("code = %v", code)
	}
	got, ok := data["guard"].(guard.Settings)
	if !ok || got.Version != 1 || !got.Enabled || got.RateLimit != 4 {
		t.Fatalf("heartbeat data = %#v", data)
	}
}
