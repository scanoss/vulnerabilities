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
	"errors"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

type CVSSResult struct {
	Vector   string  `json:"vector"`
	Version  string  `json:"version"`
	Score    float64 `json:"base_score"`
	Severity string  `json:"severity"`
	Valid    bool    `json:"valid"`
	Error    string  `json:"error,omitempty"`
}

func GetCVSS(vector string) (*CVSSResult, error) {
	result := &CVSSResult{
		Vector: vector,
		Valid:  false,
	}

	// Determine CVSS version
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1"):
		return parseCVSS31(vector)
	case strings.HasPrefix(vector, "CVSS:3.0"):
		return parseCVSS30(vector)
	case strings.Contains(vector, "AV:") && !strings.HasPrefix(vector, "CVSS:"):
		return parseCVSS20(vector)
	case strings.HasPrefix(vector, "CVSS:4.0"):
		return parseCVSS40(vector)

	default:
		return result, errors.New("unknown parser")
	}
}

func parseCVSS31(vector string) (*CVSSResult, error) {
	result := &CVSSResult{
		Vector:  vector,
		Version: "3.1",
		Valid:   false,
	}

	cvss31, err := gocvss31.ParseVector(vector)
	if err != nil {
		return nil, err
	}

	result.Score = cvss31.BaseScore()
	result.Severity = getSeverityRating(result.Score)
	result.Valid = true

	return result, nil
}

func parseCVSS30(vector string) (*CVSSResult, error) {
	result := &CVSSResult{
		Vector:  vector,
		Version: "3.0",
		Valid:   false,
	}

	cvss30, err := gocvss30.ParseVector(vector)
	if err != nil {
		return nil, err
	}

	result.Score = cvss30.BaseScore()
	result.Severity = getSeverityRating(result.Score)
	result.Valid = true

	return result, nil
}

func parseCVSS40(vector string) (*CVSSResult, error) {
	result := &CVSSResult{
		Vector:  vector,
		Version: "4.0",
		Valid:   false,
	}

	cvss40, err := gocvss40.ParseVector(vector)
	if err != nil {
		return nil, err
	}

	result.Score = cvss40.Score()
	result.Severity = getSeverityRating(result.Score)
	result.Valid = true

	return result, nil
}

func parseCVSS20(vector string) (*CVSSResult, error) {
	result := &CVSSResult{
		Vector:  vector,
		Version: "2.0",
		Valid:   false,
	}

	cvss20, err := gocvss20.ParseVector(vector)
	if err != nil {
		return nil, err
	}

	result.Score = cvss20.BaseScore()
	result.Severity = getSeverityRatingV2(result.Score)
	result.Valid = true

	return result, nil
}

// See: https://www.first.org/cvss/v3-0/specification-document - Qualitative Severity Rating Scale.
func getSeverityRating(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "None"
	}
}

// TODO: Check if there is an official severity rating.
func getSeverityRatingV2(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "None"
	}
}
