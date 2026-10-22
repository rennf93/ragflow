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
	"fmt"

	"gorm.io/gorm"

	"ragflow/internal/common"
	"ragflow/internal/dao"
	"ragflow/internal/entity"
)

// settingsName is the system_settings row holding the guard settings as JSON.
const settingsName = "guard.settings"

// Applier receives settings, normally a *Manager.
type Applier interface {
	Apply(Settings) error
}

// LoadSettings reads the stored settings; the zero value (version 0, disabled)
// when none were ever saved.
func LoadSettings(ctx context.Context) (Settings, error) {
	return loadSettings(ctx, dao.DB)
}

func loadSettings(ctx context.Context, db *gorm.DB) (Settings, error) {
	rows, err := dao.NewSystemSettingsDAO().GetByName(ctx, db, settingsName)
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if len(rows) == 0 {
		return s, nil
	}
	if err = json.Unmarshal([]byte(rows[0].Value), &s); err != nil {
		return Settings{}, fmt.Errorf("stored %s is not valid JSON: %w", settingsName, err)
	}
	return s, nil
}

// ReplaceSettings validates s and stores it with the version incremented by one.
// Validation problems come back as the second value and nothing is stored.
func ReplaceSettings(ctx context.Context, s Settings) (Settings, []error, error) {
	if errs := s.Validate(); len(errs) > 0 {
		return Settings{}, errs, nil
	}
	settingsDAO := dao.NewSystemSettingsDAO()
	err := settingsDAO.Transaction(ctx, dao.DB, func(tx *gorm.DB) error {
		current, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		s.Version = current.Version + 1
		encoded, err := json.Marshal(s)
		if err != nil {
			return err
		}
		row := &entity.SystemSettings{Name: settingsName, Value: string(encoded), Source: "admin", DataType: "json"}
		if err = entity.ValidateSystemSettingValue(*row, row.Value); err != nil {
			return err
		}
		existing, err := settingsDAO.GetByName(ctx, tx, settingsName)
		if err != nil {
			return err
		}
		if len(existing) == 0 {
			return settingsDAO.Create(ctx, tx, row)
		}
		return settingsDAO.UpdateByName(ctx, tx, settingsName, row)
	})
	if err != nil {
		return Settings{}, nil, err
	}
	return s, nil, nil
}

// ApplyStored loads the stored settings and hands them to a.
func ApplyStored(ctx context.Context, a Applier) error {
	s, err := LoadSettings(ctx)
	if err != nil {
		return err
	}
	return a.Apply(s)
}

// AddSettingsToHeartbeat puts the stored settings under the "guard" key of an
// Admin heartbeat response. When they cannot be read the response is returned
// unchanged, so a storage fault never fails a heartbeat.
func AddSettingsToHeartbeat(ctx context.Context, data map[string]interface{}) map[string]interface{} {
	s, err := LoadSettings(ctx)
	if err != nil {
		common.Error("failed to load guard settings for the heartbeat response", err)
		return data
	}
	if data == nil {
		data = map[string]interface{}{}
	}
	data["guard"] = s
	return data
}

// ApplyFromHeartbeat hands the "guard" key of a heartbeat response to a. A
// response without the key changes nothing.
func ApplyFromHeartbeat(a Applier, responseData interface{}) {
	data, ok := responseData.(map[string]interface{})
	if !ok || a == nil {
		return
	}
	raw, ok := data["guard"]
	if !ok {
		return
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		common.Error("failed to encode guard settings", err)
		return
	}
	var s Settings
	if err = json.Unmarshal(encoded, &s); err != nil {
		common.Error("failed to decode guard settings", err)
		return
	}
	if err = a.Apply(s); err != nil {
		common.Error("failed to apply guard settings", err)
	}
}
