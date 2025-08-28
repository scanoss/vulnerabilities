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

package utils

import (
	"testing"
)

func TestGetCVSS(t *testing.T) {
	tests := []struct {
		name     string
		vector   string
		expected *CVSSResult
		wantErr  bool
	}{
		{
			name:   "Valid CVSS 3.1 vector",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected: &CVSSResult{
				Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Version:  "3.1",
				Score:    9.8,
				Severity: "CRITICAL",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:   "Valid CVSS 3.0 vector",
			vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected: &CVSSResult{
				Vector:   "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Version:  "3.0",
				Score:    9.8,
				Severity: "CRITICAL",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:   "Valid CVSS 2.0 vector",
			vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			expected: &CVSSResult{
				Vector:   "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				Version:  "2.0",
				Score:    7.5,
				Severity: "HIGH",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:   "Valid CVSS 4.0 vector",
			vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			expected: &CVSSResult{
				Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				Version:  "4.0",
				Score:    9.3,
				Severity: "CRITICAL",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:     "Invalid vector format",
			vector:   "INVALID:VECTOR",
			expected: &CVSSResult{Vector: "INVALID:VECTOR", Valid: false},
			wantErr:  true,
		},
		{
			name:     "Empty vector",
			vector:   "",
			expected: &CVSSResult{Vector: "", Valid: false},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetCVSS(tt.vector)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetCVSS() expected error but got none")
				}
				if result.Valid != tt.expected.Valid {
					t.Errorf("GetCVSS() Valid = %v, expected %v", result.Valid, tt.expected.Valid)
				}
				if result.Vector != tt.expected.Vector {
					t.Errorf("GetCVSS() Vector = %v, expected %v", result.Vector, tt.expected.Vector)
				}
				return
			}

			if err != nil {
				t.Errorf("GetCVSS() unexpected error: %v", err)
				return
			}

			if result.Vector != tt.expected.Vector {
				t.Errorf("GetCVSS() Vector = %v, expected %v", result.Vector, tt.expected.Vector)
			}
			if result.Version != tt.expected.Version {
				t.Errorf("GetCVSS() Version = %v, expected %v", result.Version, tt.expected.Version)
			}
			if result.Score != tt.expected.Score {
				t.Errorf("GetCVSS() Score = %v, expected %v", result.Score, tt.expected.Score)
			}
			if result.Severity != tt.expected.Severity {
				t.Errorf("GetCVSS() Severity = %v, expected %v", result.Severity, tt.expected.Severity)
			}
			if result.Valid != tt.expected.Valid {
				t.Errorf("GetCVSS() Valid = %v, expected %v", result.Valid, tt.expected.Valid)
			}
		})
	}
}

func TestGetSeverityRating(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		expected string
	}{
		{"Critical score 10.0", 10.0, "CRITICAL"},
		{"Critical score 9.0", 9.0, "CRITICAL"},
		{"High score 8.9", 8.9, "HIGH"},
		{"High score 7.0", 7.0, "HIGH"},
		{"Medium score 6.9", 6.9, "MEDIUM"},
		{"Medium score 4.0", 4.0, "MEDIUM"},
		{"Low score 3.9", 3.9, "LOW"},
		{"Low score 0.1", 0.1, "LOW"},
		{"None score 0.0", 0.0, "None"},
		{"None negative score", -1.0, "None"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getSeverityRating(tt.score)
			if result != tt.expected {
				t.Errorf("getSeverityRating(%v) = %v, expected %v", tt.score, result, tt.expected)
			}
		})
	}
}

func TestGetSeverityRatingV2(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		expected string
	}{
		{"High score 10.0", 10.0, "HIGH"},
		{"High score 7.0", 7.0, "HIGH"},
		{"Medium score 6.9", 6.9, "MEDIUM"},
		{"Medium score 4.0", 4.0, "MEDIUM"},
		{"Low score 3.9", 3.9, "LOW"},
		{"Low score 0.1", 0.1, "LOW"},
		{"None score 0.0", 0.0, "None"},
		{"None negative score", -1.0, "None"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getSeverityRatingV2(tt.score)
			if result != tt.expected {
				t.Errorf("getSeverityRatingV2(%v) = %v, expected %v", tt.score, result, tt.expected)
			}
		})
	}
}

func TestParseCVSS31(t *testing.T) {
	tests := []struct {
		name     string
		vector   string
		expected *CVSSResult
		wantErr  bool
	}{
		{
			name:   "Valid CVSS 3.1 high severity",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected: &CVSSResult{
				Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Version:  "3.1",
				Score:    9.8,
				Severity: "CRITICAL",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:   "Valid CVSS 3.1 low severity",
			vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
			expected: &CVSSResult{
				Vector:   "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
				Version:  "3.1",
				Score:    3.8,
				Severity: "LOW",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:    "Invalid CVSS 3.1 vector",
			vector:  "CVSS:3.1/INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCVSS31(tt.vector)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseCVSS31() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("parseCVSS31() unexpected error: %v", err)
				return
			}

			if result.Vector != tt.expected.Vector {
				t.Errorf("parseCVSS31() Vector = %v, expected %v", result.Vector, tt.expected.Vector)
			}
			if result.Version != tt.expected.Version {
				t.Errorf("parseCVSS31() Version = %v, expected %v", result.Version, tt.expected.Version)
			}
			if result.Score != tt.expected.Score {
				t.Errorf("parseCVSS31() Score = %v, expected %v", result.Score, tt.expected.Score)
			}
			if result.Severity != tt.expected.Severity {
				t.Errorf("parseCVSS31() Severity = %v, expected %v", result.Severity, tt.expected.Severity)
			}
			if result.Valid != tt.expected.Valid {
				t.Errorf("parseCVSS31() Valid = %v, expected %v", result.Valid, tt.expected.Valid)
			}
		})
	}
}

func TestParseCVSS30(t *testing.T) {
	tests := []struct {
		name     string
		vector   string
		expected *CVSSResult
		wantErr  bool
	}{
		{
			name:   "Valid CVSS 3.0 vector",
			vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected: &CVSSResult{
				Vector:   "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Version:  "3.0",
				Score:    9.8,
				Severity: "CRITICAL",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:    "Invalid CVSS 3.0 vector",
			vector:  "CVSS:3.0/INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCVSS30(tt.vector)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseCVSS30() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("parseCVSS30() unexpected error: %v", err)
				return
			}

			if result.Vector != tt.expected.Vector {
				t.Errorf("parseCVSS30() Vector = %v, expected %v", result.Vector, tt.expected.Vector)
			}
			if result.Version != tt.expected.Version {
				t.Errorf("parseCVSS30() Version = %v, expected %v", result.Version, tt.expected.Version)
			}
			if result.Score != tt.expected.Score {
				t.Errorf("parseCVSS30() Score = %v, expected %v", result.Score, tt.expected.Score)
			}
			if result.Severity != tt.expected.Severity {
				t.Errorf("parseCVSS30() Severity = %v, expected %v", result.Severity, tt.expected.Severity)
			}
			if result.Valid != tt.expected.Valid {
				t.Errorf("parseCVSS30() Valid = %v, expected %v", result.Valid, tt.expected.Valid)
			}
		})
	}
}

func TestParseCVSS40(t *testing.T) {
	tests := []struct {
		name     string
		vector   string
		expected *CVSSResult
		wantErr  bool
	}{
		{
			name:   "Valid CVSS 4.0 vector",
			vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			expected: &CVSSResult{
				Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				Version:  "4.0",
				Score:    9.3,
				Severity: "CRITICAL",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:    "Invalid CVSS 4.0 vector",
			vector:  "CVSS:4.0/INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCVSS40(tt.vector)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseCVSS40() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("parseCVSS40() unexpected error: %v", err)
				return
			}

			if result.Vector != tt.expected.Vector {
				t.Errorf("parseCVSS40() Vector = %v, expected %v", result.Vector, tt.expected.Vector)
			}
			if result.Version != tt.expected.Version {
				t.Errorf("parseCVSS40() Version = %v, expected %v", result.Version, tt.expected.Version)
			}
			if result.Score != tt.expected.Score {
				t.Errorf("parseCVSS40() Score = %v, expected %v", result.Score, tt.expected.Score)
			}
			if result.Severity != tt.expected.Severity {
				t.Errorf("parseCVSS40() Severity = %v, expected %v", result.Severity, tt.expected.Severity)
			}
			if result.Valid != tt.expected.Valid {
				t.Errorf("parseCVSS40() Valid = %v, expected %v", result.Valid, tt.expected.Valid)
			}
		})
	}
}

func TestParseCVSS20(t *testing.T) {
	tests := []struct {
		name     string
		vector   string
		expected *CVSSResult
		wantErr  bool
	}{
		{
			name:   "Valid CVSS 2.0 vector",
			vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			expected: &CVSSResult{
				Vector:   "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				Version:  "2.0",
				Score:    7.5,
				Severity: "HIGH",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:   "Valid CVSS 2.0 low severity",
			vector: "AV:L/AC:H/Au:S/C:N/I:N/A:P",
			expected: &CVSSResult{
				Vector:   "AV:L/AC:H/Au:S/C:N/I:N/A:P",
				Version:  "2.0",
				Score:    1.0,
				Severity: "LOW",
				Valid:    true,
			},
			wantErr: false,
		},
		{
			name:    "Invalid CVSS 2.0 vector",
			vector:  "AV:INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCVSS20(tt.vector)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseCVSS20() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("parseCVSS20() unexpected error: %v", err)
				return
			}

			if result.Vector != tt.expected.Vector {
				t.Errorf("parseCVSS20() Vector = %v, expected %v", result.Vector, tt.expected.Vector)
			}
			if result.Version != tt.expected.Version {
				t.Errorf("parseCVSS20() Version = %v, expected %v", result.Version, tt.expected.Version)
			}
			if result.Score != tt.expected.Score {
				t.Errorf("parseCVSS20() Score = %v, expected %v", result.Score, tt.expected.Score)
			}
			if result.Severity != tt.expected.Severity {
				t.Errorf("parseCVSS20() Severity = %v, expected %v", result.Severity, tt.expected.Severity)
			}
			if result.Valid != tt.expected.Valid {
				t.Errorf("parseCVSS20() Valid = %v, expected %v", result.Valid, tt.expected.Valid)
			}
		})
	}
}
