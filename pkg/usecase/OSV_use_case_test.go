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

package usecase

import (
	"context"
	"testing"

	compHelper "github.com/scanoss/go-component-helper/componenthelper"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/vulnerabilities/pkg/config"
)

func TestOSVUseCase(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()

	serverConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	testCases := []struct {
		name  string
		input []compHelper.Component
	}{
		{
			name: "OSV Use Case Test",
			input: []compHelper.Component{
				{
					Purl:        "pkg:pypi/mlflow",
					Requirement: "2.3.0",
					Version:     "2.3.0",
					Status: domain.ComponentStatus{
						Message:    "",
						StatusCode: domain.Success,
					},
				},
				{
					Purl: "pkg:golang/github.com/navidrome/navidrome",
					Status: domain.ComponentStatus{
						Message:    "",
						StatusCode: domain.Success,
					},
				},
			},
		},
	}
	OSVUseCase := NewOSVUseCase(s, serverConfig)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := OSVUseCase.Execute(ctx, tc.input)
			if len(r.Components) == 0 {
				t.Errorf("Expected Purls to have elements, got empty slice")
			}
		})
	}
}

func TestGetRepoURL(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()

	serverConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	us := NewOSVUseCase(s, serverConfig)

	tests := []struct {
		name     string
		purl     string
		expected *string
	}{
		// Direct type-based hosts
		{
			name:     "GitHub PURL",
			purl:     "pkg:github/owner/repo@v1.0.0",
			expected: strPtr("https://github.com/owner/repo"),
		},
		{
			name:     "GitLab PURL",
			purl:     "pkg:gitlab/owner/repo@v1.0.0",
			expected: strPtr("https://gitlab.com/owner/repo"),
		},
		{
			name:     "Bitbucket PURL",
			purl:     "pkg:bitbucket/owner/repo@v1.0.0",
			expected: strPtr("https://bitbucket.org/owner/repo"),
		},
		{
			name:     "Gitee PURL",
			purl:     "pkg:gitee/owner/repo@v1.0.0",
			expected: strPtr("https://gitee.com/owner/repo"),
		},
		// repository_url qualifier-based hosts
		{
			name:     "GNOME GitLab via repository_url",
			purl:     "pkg:generic/gnome.org/GNOME/gimp@GIMP_2_10_36?repository_url=https://gitlab.gnome.org/GNOME/gimp",
			expected: strPtr("https://gitlab.gnome.org/GNOME/gimp"),
		},
		{
			name:     "Freedesktop GitLab via repository_url",
			purl:     "pkg:generic/freedesktop.org/mesa/mesa@mesa-24.0.0?repository_url=https://gitlab.freedesktop.org/mesa/mesa",
			expected: strPtr("https://gitlab.freedesktop.org/mesa/mesa"),
		},
		{
			name:     "Xiph GitLab via repository_url",
			purl:     "pkg:generic/xiph.org/xiph/opus@v1.6?repository_url=https://gitlab.xiph.org/xiph/opus",
			expected: strPtr("https://gitlab.xiph.org/xiph/opus"),
		},
		{
			name:     "Fraunhofer HHI via repository_url",
			purl:     "pkg:generic/vcgit.hhi.fraunhofer.de/jvet/VVCSoftware_VTM@VTM-15.0?repository_url=https://vcgit.hhi.fraunhofer.de/jvet/VVCSoftware_VTM",
			expected: strPtr("https://vcgit.hhi.fraunhofer.de/jvet/VVCSoftware_VTM"),
		},
		{
			name:     "CodeLinaro via repository_url",
			purl:     "pkg:generic/codelinaro.org/linaro/qcomlt/kernel@v6.0?repository_url=https://git.codelinaro.org/linaro/qcomlt/kernel",
			expected: strPtr("https://git.codelinaro.org/linaro/qcomlt/kernel"),
		},
		{
			name:     "Yocto Project via repository_url",
			purl:     "pkg:generic/yoctoproject.org/poky@yocto-4.0?repository_url=https://git.yoctoproject.org/poky",
			expected: strPtr("https://git.yoctoproject.org/poky"),
		},
		{
			name:     "Trusted Firmware via repository_url",
			purl:     "pkg:generic/trustedfirmware.org/TF-A/trusted-firmware-a@lts-v2.12?repository_url=https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git",
			expected: strPtr("https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git"),
		},
		{
			name:     "Sourceware via repository_url",
			purl:     "pkg:generic/sourceware.org/glibc@glibc-2.39?repository_url=https://sourceware.org/git/glibc.git",
			expected: strPtr("https://sourceware.org/git/glibc.git"),
		},
		{
			name:     "GitCode via repository_url",
			purl:     "pkg:generic/gitcode.com/openharmony/docs@v1.0.0?repository_url=https://gitcode.com/openharmony/docs",
			expected: strPtr("https://gitcode.com/openharmony/docs"),
		},
		{
			name:     "Eclipse via repository_url",
			purl:     "pkg:generic/eclipse.org/jgit/jgit@v7.0.0?repository_url=https://git.eclipse.org/c/jgit/jgit.git",
			expected: strPtr("https://git.eclipse.org/c/jgit/jgit.git"),
		},
		{
			name:     "KDE Invent via repository_url",
			purl:     "pkg:generic/invent.kde.org/plasma/plasma-desktop@v6.0.0?repository_url=https://invent.kde.org/plasma/plasma-desktop",
			expected: strPtr("https://invent.kde.org/plasma/plasma-desktop"),
		},
		{
			name:     "Gitee via repository_url",
			purl:     "pkg:generic/openharmony/docs@v5.0.0?repository_url=https://gitee.com/openharmony/docs",
			expected: strPtr("https://gitee.com/openharmony/docs"),
		},
		// Non-git PURL returns nil
		{
			name:     "PyPI PURL returns nil",
			purl:     "pkg:pypi/requests@2.28.0",
			expected: nil,
		},
		// Invalid PURL returns nil
		{
			name:     "Invalid PURL returns nil",
			purl:     "not-a-purl",
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := us.getRepoURL(tc.purl)
			if tc.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %s", *result)
				}
				return
			}
			if result == nil {
				t.Errorf("expected %s, got nil", *tc.expected)
				return
			}
			if *result != *tc.expected {
				t.Errorf("expected %s, got %s", *tc.expected, *result)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
