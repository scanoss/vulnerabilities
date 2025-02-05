// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2025 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/golobby/config/v3"
	"github.com/golobby/config/v3/pkg/feeder"
)

func TestServerConfig(t *testing.T) {
	dbUser := "test-user"
	err := os.Setenv("DB_USER", dbUser)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when creating new config instance", err)
	}
	cfg, err := NewServerConfig(nil)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when creating new config instance", err)
	}
	if cfg.Database.User != dbUser {
		t.Errorf("DB user '%v' doesn't match expected: %v", cfg.Database.User, dbUser)
	}
	fmt.Printf("Server Config1: %+v\n", cfg)
	err = os.Unsetenv("DB_USER")
	if err != nil {
		fmt.Printf("Warning: Problem runn Unsetenv: %v\n", err)
	}
}

func TestServerConfigDotEnv(t *testing.T) {
	err := os.Unsetenv("DB_USER")
	if err != nil {
		fmt.Printf("Warning: Problem runn Unsetenv: %v\n", err)
	}
	dbUser := "env-user"
	var feeders []config.Feeder
	feeders = append(feeders, feeder.DotEnv{Path: "tests/dot-env"})
	cfg, err := NewServerConfig(feeders)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when creating new config instance", err)
	}
	if cfg.Database.User != dbUser {
		t.Errorf("DB user '%v' doesn't match expected: %v", cfg.Database.User, dbUser)
	}
	fmt.Printf("Server Config2: %+v\n", cfg)
}

func TestServerConfigJson(t *testing.T) {
	err := os.Unsetenv("DB_USER")
	if err != nil {
		fmt.Printf("Warning: Problem runn Unsetenv: %v\n", err)
	}
	dbUser := "json-user"
	var feeders []config.Feeder
	feeders = append(feeders, feeder.Json{Path: "tests/env.json"})
	cfg, err := NewServerConfig(feeders)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when creating new config instance", err)
	}
	if cfg.Database.User != dbUser {
		t.Errorf("DB user '%v' doesn't match expected: %v", cfg.Database.User, dbUser)
	}
	fmt.Printf("Server Config3: %+v\n", cfg)
}

func TestConfigValidation(t *testing.T) {
	t.Run("configuration validation scenarios", func(t *testing.T) {
		// Setup
		feeders := []config.Feeder{feeder.Json{Path: "tests/env.json"}}
		cfg, err := NewServerConfig(feeders)
		if err != nil {
			t.Fatalf("failed to create config instance: %v", err)
		}

		tests := []struct {
			name        string
			modifyConf  func(*ServerConfig)
			expectError bool
		}{
			{
				name: "invalid when all sources disabled",
				modifyConf: func(c *ServerConfig) {
					c.Source.OSV.Enabled = false
					c.Source.SCANOSS.Enabled = false
				},
				expectError: true,
			},
			{
				name: "invalid with empty OSV API base URL",
				modifyConf: func(c *ServerConfig) {
					c.Source.OSV.APIBaseURL = ""
				},
				expectError: true,
			},
			{
				name: "valid config",
				modifyConf: func(c *ServerConfig) {
				},
				expectError: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				testCfg := *cfg
				tt.modifyConf(&testCfg)
				err = IsValidConfig(&testCfg)

				if tt.expectError && err == nil {
					t.Errorf("expected validation error, got nil")
				}
				if !tt.expectError && err != nil {
					t.Errorf("unexpected validation error: %v", err)
				}
			})
		}
	})
}
