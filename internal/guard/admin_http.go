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
	"github.com/gin-gonic/gin"

	"ragflow/internal/common"
)

// AdminHandlers serve the guard settings routes of the Admin service. Applier,
// when set, receives each stored version so the admin server's own guard follows.
type AdminHandlers struct {
	Applier Applier
}

// Get returns the stored settings.
func (h AdminHandlers) Get(c *gin.Context) {
	s, err := LoadSettings(c.Request.Context())
	if err != nil {
		common.ErrorWithCode(c, common.CodeServerError, err.Error())
		return
	}
	common.SuccessWithData(c, s, "")
}

// Put validates and replaces the stored settings. The version in the body is
// ignored: the stored version is incremented by one.
func (h AdminHandlers) Put(c *gin.Context) {
	var s Settings
	if err := c.ShouldBindJSON(&s); err != nil {
		common.ErrorWithCode(c, common.CodeBadRequest, "Invalid guard settings JSON: "+err.Error())
		return
	}
	stored, problems, err := ReplaceSettings(c.Request.Context(), s)
	if len(problems) > 0 {
		messages := make([]string, len(problems))
		for i, p := range problems {
			messages[i] = p.Error()
		}
		common.ResponseWithCodeData(c, common.CodeBadRequest, gin.H{"errors": messages}, "Invalid guard settings")
		return
	}
	if err != nil {
		common.ErrorWithCode(c, common.CodeServerError, err.Error())
		return
	}
	if h.Applier != nil {
		if err = h.Applier.Apply(stored); err != nil {
			common.Error("admin server failed to apply stored guard settings", err)
		}
	}
	common.SuccessWithData(c, stored, "")
}
