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
	"errors"
	"sync"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"ragflow/internal/common"
	"ragflow/internal/server/config"
)

type instance struct {
	handler   gin.HandlerFunc
	closeFn   func()
	inflight  atomic.Int64
	retired   atomic.Bool
	closeOnce sync.Once
}

func (i *instance) release() {
	if i.inflight.Add(-1) == 0 && i.retired.Load() {
		i.closeOnce.Do(i.closeFn)
	}
}

func (i *instance) retire() {
	i.retired.Store(true)
	if i.inflight.Load() == 0 {
		i.closeOnce.Do(i.closeFn)
	}
}

// Manager holds the current guard behind an atomic pointer. Middleware is
// registered once and follows whichever guard Apply installed last.
type Manager struct {
	trustedProxies []string
	kvrocks        config.KvrocksConfig
	build          func(Settings, []string, config.KvrocksConfig) (gin.HandlerFunc, func(), error)

	mu      sync.Mutex
	version int64
	current atomic.Pointer[instance]
}

// NewManager returns a manager with no guard: requests pass through until the
// first enabled settings are applied.
func NewManager(trustedProxies []string, kvrocks config.KvrocksConfig) *Manager {
	return &Manager{trustedProxies: trustedProxies, kvrocks: kvrocks, build: New}
}

// Apply installs the guard described by s. A version at or below the current
// one is ignored. Invalid settings or a failed build keep the current guard and
// version, and return the error.
func (m *Manager) Apply(s Settings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Version <= m.version {
		return nil
	}
	var next *instance
	if s.Enabled {
		if errs := s.Validate(); len(errs) > 0 {
			return m.reject(s.Version, errors.Join(errs...))
		}
		handler, closeFn, err := m.build(s, m.trustedProxies, m.kvrocks)
		if err != nil {
			return m.reject(s.Version, err)
		}
		next = &instance{handler: handler, closeFn: closeFn}
	}
	m.version = s.Version
	if old := m.current.Swap(next); old != nil {
		old.retire()
	}
	return nil
}

func (m *Manager) reject(version int64, err error) error {
	common.Error("request guard settings rejected, keeping the current guard", err, zap.Int64("version", version))
	return err
}

// Close retires the current guard.
func (m *Manager) Close() {
	if old := m.current.Swap(nil); old != nil {
		old.retire()
	}
}

func (m *Manager) acquire() *instance {
	for {
		inst := m.current.Load()
		if inst == nil {
			return nil
		}
		inst.inflight.Add(1)
		if !inst.retired.Load() {
			return inst
		}
		inst.release()
	}
}

// Middleware runs the current guard, or passes through when there is none.
func (m *Manager) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if healthPaths[c.Request.URL.Path] {
			c.Next()
			return
		}
		inst := m.acquire()
		if inst == nil {
			c.Next()
			return
		}
		defer inst.release()
		inst.handler(c)
	}
}
