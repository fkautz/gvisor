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
		if err := json.NewEncoder(rw).Encode(casimirReadResponse{Continue: true}); err != nil {
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

func TestCasimirReadWithholdsSuccessfulReturnWhenReceiptRejected(t *testing.T) {
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
		_ = json.NewEncoder(rw).Encode(casimirReadResponse{Error: "receipt rejected"})
		_ = rw.Flush()
	}()

	n, err := newCasimirDataClient(clientConn).read("renamed-new", make([]byte, len("upper")), 0)
	if err == nil || n != 0 {
		t.Fatalf("read() = (%d, %v), want fail-closed no successful return", n, err)
	}
}

type unexpectedCasimirReceipt struct {
	receipt casimirExposureReceipt
}

func (e *unexpectedCasimirReceipt) Error() string {
	data, _ := json.Marshal(e.receipt)
	return "unexpected Casimir receipt: " + string(data)
}
