package fsgofer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"testing"
)

func TestCasimirReadReturnsOnlyAfterExactExposureReceipt(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn))
		var request casimirReadRequest
		if err := json.NewDecoder(rw).Decode(&request); err != nil {
			serverDone <- err
			return
		}
		if err := json.NewEncoder(rw).Encode(casimirReadResponse{
			Data:       []byte("upper"),
			ExposureID: 41,
		}); err != nil {
			serverDone <- err
			return
		}
		if err := rw.Flush(); err != nil {
			serverDone <- err
			return
		}
		var receipt casimirExposureReceipt
		if err := json.NewDecoder(rw).Decode(&receipt); err != nil {
			serverDone <- err
			return
		}
		if receipt.Operation != "state-root-receipt" ||
			receipt.ReceiptKind != "vfs-read-return" ||
			receipt.ExposureID != 41 ||
			receipt.Path != "renamed-new" ||
			receipt.Offset != 7 ||
			receipt.Length != uint64(len("upper")) {
			serverDone <- &unexpectedCasimirReceipt{receipt: receipt}
			return
		}
		if err := json.NewEncoder(rw).Encode(casimirReadResponse{
			Operation:   receipt.Operation,
			ReceiptKind: receipt.ReceiptKind,
			Continue:    true,
			ExposureID:  receipt.ExposureID,
			Path:        receipt.Path,
			Offset:      receipt.Offset,
			Length:      receipt.Length,
		}); err != nil {
			serverDone <- err
			return
		}
		serverDone <- rw.Flush()
	}()

	dst := make([]byte, len("upper"))
	n, err := newCasimirDataClient(clientConn).read("renamed-new", dst, 7)
	if err != nil {
		t.Fatalf("read() error = %v", err)
	}
	if n != uint64(len(dst)) || !bytes.Equal(dst, []byte("upper")) {
		t.Fatalf("read() = (%d, %q), want exact upper bytes", n, dst)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestCasimirReadWithholdsSuccessfulReturnWhenReceiptAcknowledgementIsNotExact(t *testing.T) {
	valid := casimirReadResponse{
		Operation:   "state-root-receipt",
		ReceiptKind: "vfs-read-return",
		Continue:    true,
		ExposureID:  42,
		Path:        "renamed-new",
		Offset:      3,
		Length:      uint64(len("upper")),
	}
	tests := []struct {
		name   string
		mutate func(*casimirReadResponse)
	}{
		{name: "bare continue", mutate: func(a *casimirReadResponse) {
			*a = casimirReadResponse{Continue: true}
		}},
		{name: "stale exposure", mutate: func(a *casimirReadResponse) { a.ExposureID-- }},
		{name: "out of order kind", mutate: func(a *casimirReadResponse) { a.ReceiptKind = "page-installed" }},
		{name: "mismatched path", mutate: func(a *casimirReadResponse) { a.Path = "other" }},
		{name: "mismatched offset", mutate: func(a *casimirReadResponse) { a.Offset++ }},
		{name: "mismatched length", mutate: func(a *casimirReadResponse) { a.Length++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			go func() {
				defer serverConn.Close()
				rw := bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn))
				var request casimirReadRequest
				if err := json.NewDecoder(rw).Decode(&request); err != nil {
					return
				}
				if err := json.NewEncoder(rw).Encode(casimirReadResponse{
					Data:       []byte("upper"),
					ExposureID: 42,
				}); err != nil {
					return
				}
				if err := rw.Flush(); err != nil {
					return
				}
				var receipt casimirExposureReceipt
				if err := json.NewDecoder(rw).Decode(&receipt); err != nil {
					return
				}
				acknowledgement := valid
				test.mutate(&acknowledgement)
				_ = json.NewEncoder(rw).Encode(acknowledgement)
				_ = rw.Flush()
			}()

			n, err := newCasimirDataClient(clientConn).read("renamed-new", make([]byte, len("upper")), 3)
			if err == nil || n != 0 {
				t.Fatalf("read() = (%d, %v), want fail-closed no successful return", n, err)
			}
		})
	}
}

type unexpectedCasimirReceipt struct {
	receipt casimirExposureReceipt
}

func (e *unexpectedCasimirReceipt) Error() string {
	data, _ := json.Marshal(e.receipt)
	return "unexpected Casimir receipt: " + string(data)
}
