package fsgofer

import "testing"

func TestLogicalCasimirPathStripsOnlyMountRoot(t *testing.T) {
	if got, ok := logicalCasimirPath("/root", "/root/usr/bin/cat"); !ok || got != "usr/bin/cat" {
		t.Fatalf("logicalCasimirPath(in-root) = (%q, %t), want usr/bin/cat", got, ok)
	}
	for _, path := range []string{"/root", "/outside/cat", "/rooted/cat"} {
		if got, ok := logicalCasimirPath("/root", path); ok || got != "" {
			t.Fatalf("logicalCasimirPath(%q) = (%q, %t), want rejection", path, got, ok)
		}
	}
}
