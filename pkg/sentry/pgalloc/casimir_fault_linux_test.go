//go:build linux

package pgalloc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"testing"
)

type recordingCasimirWakeup struct {
	calls     []string
	pageStart uint64
	pageSize  uint64
	data      []byte
}

func (w *recordingCasimirWakeup) continueFault(pageStart, pageSize uint64) error {
	w.calls = append(w.calls, "continue")
	w.pageStart, w.pageSize = pageStart, pageSize
	return nil
}

func (w *recordingCasimirWakeup) zeroFault(pageStart, pageSize uint64) error {
	w.calls = append(w.calls, "zero")
	w.pageStart, w.pageSize = pageStart, pageSize
	return nil
}

func (w *recordingCasimirWakeup) copyFault(pageStart, pageSize uint64, data []byte) error {
	w.calls = append(w.calls, "copy")
	w.pageStart, w.pageSize = pageStart, pageSize
	w.data = append([]byte(nil), data...)
	return nil
}

func TestResolveCasimirFaultUsesExplicitActionAsSoleWakeupAuthority(t *testing.T) {
	pageSize := uint64(4096)
	tests := []struct {
		name     string
		mode     string
		response casimirFaultResponse
		want     string
	}{
		{
			name: "copy",
			mode: "missing",
			response: casimirFaultResponse{
				FaultAction: "copy",
				Data:        bytes.Repeat([]byte{0x5a}, int(pageSize)),
			},
			want: "copy",
		},
		{
			name: "continue",
			mode: "minor",
			response: casimirFaultResponse{
				FaultAction: "continue",
			},
			want: "continue",
		},
		{
			name: "zero",
			mode: "missing",
			response: casimirFaultResponse{
				FaultAction: "zero",
			},
			want: "zero",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, wakeup, err := exchangeCasimirFault(t, test.mode, test.response)
			if err != nil {
				t.Fatalf("resolveCasimirFault() error = %v", err)
			}
			if request.Operation != "fault" || request.FaultMode != test.mode ||
				request.Offset != 4096 || request.Length != pageSize {
				t.Fatalf("wire request = %+v, want explicit %q fault mode and exact range", request, test.mode)
			}
			if len(wakeup.calls) != 1 || wakeup.calls[0] != test.want {
				t.Fatalf("wakeup calls = %v, want only %q from explicit action", wakeup.calls, test.want)
			}
			if wakeup.pageStart != 0x12000 || wakeup.pageSize != pageSize {
				t.Fatalf("wakeup range = (%#x, %d), want (%#x, %d)", wakeup.pageStart, wakeup.pageSize, uint64(0x12000), pageSize)
			}
			if test.want == "copy" && !bytes.Equal(wakeup.data, test.response.Data) {
				t.Fatal("copy wakeup did not receive exact verified response bytes")
			}
		})
	}
}

func TestResolveCasimirFaultRejectsWithoutWakeup(t *testing.T) {
	page := bytes.Repeat([]byte{0x5a}, 4096)
	tests := []struct {
		name     string
		mode     string
		response casimirFaultResponse
	}{
		{name: "missing action", mode: "missing", response: casimirFaultResponse{Data: page}},
		{name: "unknown action", mode: "missing", response: casimirFaultResponse{FaultAction: "wake", Data: page}},
		{name: "fatal", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true, Error: "verification failed"}},
		{name: "fatal without error", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true}},
		{name: "fatal with data", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true, Error: "verification failed", Data: page}},
		{name: "copy error", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Error: "verification failed", Data: page}},
		{name: "copy fatal", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Fatal: true, Data: page}},
		{name: "copy continue", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Continue: true, Data: page}},
		{name: "copy zero", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Zero: true, Data: page}},
		{name: "copy without data", mode: "missing", response: casimirFaultResponse{FaultAction: "copy"}},
		{name: "copy short data", mode: "missing", response: casimirFaultResponse{FaultAction: "copy", Data: page[:4095]}},
		{name: "copy for minor", mode: "minor", response: casimirFaultResponse{FaultAction: "copy", Data: page}},
		{name: "continue for missing", mode: "missing", response: casimirFaultResponse{FaultAction: "continue", Continue: true}},
		{name: "continue with error", mode: "minor", response: casimirFaultResponse{FaultAction: "continue", Error: "verification failed"}},
		{name: "continue with fatal", mode: "minor", response: casimirFaultResponse{FaultAction: "continue", Fatal: true}},
		{name: "continue with data", mode: "minor", response: casimirFaultResponse{FaultAction: "continue", Continue: true, Data: page}},
		{name: "continue with zero", mode: "minor", response: casimirFaultResponse{FaultAction: "continue", Continue: true, Zero: true}},
		{name: "zero for minor", mode: "minor", response: casimirFaultResponse{FaultAction: "zero", Zero: true}},
		{name: "zero with error", mode: "missing", response: casimirFaultResponse{FaultAction: "zero", Error: "verification failed"}},
		{name: "zero with fatal", mode: "missing", response: casimirFaultResponse{FaultAction: "zero", Fatal: true}},
		{name: "zero with data", mode: "missing", response: casimirFaultResponse{FaultAction: "zero", Zero: true, Data: page}},
		{name: "zero with continue", mode: "missing", response: casimirFaultResponse{FaultAction: "zero", Zero: true, Continue: true}},
		{name: "fatal with zero", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true, Error: "verification failed", Zero: true}},
		{name: "fatal with continue", mode: "missing", response: casimirFaultResponse{FaultAction: "fatal", Fatal: true, Error: "verification failed", Continue: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, wakeup, err := exchangeCasimirFault(t, test.mode, test.response)
			if err == nil {
				t.Fatal("resolveCasimirFault() error = nil, want fail-closed rejection")
			}
			if request.FaultMode != test.mode {
				t.Fatalf("wire request fault mode = %q, want %q", request.FaultMode, test.mode)
			}
			if len(wakeup.calls) != 0 {
				t.Fatalf("rejected response issued wakeups %v", wakeup.calls)
			}
		})
	}
}

func TestResolveCasimirFaultRejectsMalformedResponseWithoutWakeup(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		var request casimirFaultRequest
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			return
		}
		_, _ = server.Write([]byte("{\"fault_action\":\n"))
	}()
	wakeup := &recordingCasimirWakeup{}
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	if err := resolveCasimirFault(rw, wakeup, "missing", 4096, 0x12345, 4096); err == nil {
		t.Fatal("resolveCasimirFault() error = nil, want malformed-response rejection")
	}
	if len(wakeup.calls) != 0 {
		t.Fatalf("malformed response issued wakeups %v", wakeup.calls)
	}
}

func exchangeCasimirFault(t testing.TB, mode string, response casimirFaultResponse) (casimirFaultRequest, *recordingCasimirWakeup, error) {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	requests := make(chan casimirFaultRequest, 1)
	serverErrors := make(chan error, 1)
	go func() {
		defer server.Close()
		var request casimirFaultRequest
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			serverErrors <- err
			return
		}
		requests <- request
		serverErrors <- json.NewEncoder(server).Encode(response)
	}()
	wakeup := &recordingCasimirWakeup{}
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	err := resolveCasimirFault(rw, wakeup, mode, 4096, 0x12345, 4096)
	request := <-requests
	if serverErr := <-serverErrors; serverErr != nil {
		t.Fatalf("fault response server error = %v", serverErr)
	}
	return request, wakeup, err
}
