// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcs

import (
	"errors"
	"io"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/api/googleapi"
)

func TestReaderOpenErrorPreservesRestoreDecisions(t *testing.T) {
	for _, tc := range []struct {
		code int
		want error
	}{
		{statusNotFound, unix.ENOENT},
		{statusForbidden, unix.EACCES},
		{statusUnauthorized, unix.EACCES},
		{statusRangeNotSatisfiable, io.EOF},
	} {
		got := readerOpenError(&googleapi.Error{Code: tc.code})
		if !errors.Is(got, tc.want) {
			t.Errorf("readerOpenError(HTTP %d) = %v, want %v", tc.code, got, tc.want)
		}
	}

	transient := &googleapi.Error{Code: 503}
	got := readerOpenError(transient)
	if errors.Is(got, unix.ENOENT) || !errors.Is(got, transient) {
		t.Fatalf("readerOpenError(HTTP 503) = %v, want wrapped transient failure", got)
	}
}
