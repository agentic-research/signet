package git

import (
	"bufio"
	"os"
	"testing"
	"time"
)

func TestGetStatusWriter_FdZeroDefaultsStderr(t *testing.T) {
	w, cleanup := getStatusWriter(0)
	t.Cleanup(cleanup)

	if w != os.Stderr {
		t.Fatalf("statusFd=0: expected os.Stderr, got %T", w)
	}
}

func TestGetStatusWriter_FdOneIsStdout(t *testing.T) {
	w, cleanup := getStatusWriter(1)
	t.Cleanup(cleanup)

	if w != os.Stdout {
		t.Fatalf("statusFd=1: expected os.Stdout, got %T", w)
	}
}

func TestGetStatusWriter_FdTwoIsStderr(t *testing.T) {
	w, cleanup := getStatusWriter(2)
	t.Cleanup(cleanup)

	if w != os.Stderr {
		t.Fatalf("statusFd=2: expected os.Stderr, got %T", w)
	}
}

func TestGetStatusWriter_CustomFdReturnsFileAndCleanupCloses(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	writer, cleanup := getStatusWriter(int(w.Fd()))

	got, ok := writer.(*os.File)
	if !ok {
		t.Fatalf("custom fd: expected *os.File, got %T", writer)
	}
	if got.Fd() != w.Fd() {
		t.Fatalf("custom fd: returned file wraps fd %d, want %d", got.Fd(), w.Fd())
	}

	const line = "[GNUPG:] CUSTOM_FD_TEST"
	if _, err := got.WriteString(line + "\n"); err != nil {
		t.Fatalf("write to status fd: %v", err)
	}

	scanner := bufio.NewScanner(r)
	done := make(chan struct{})
	var read string
	go func() {
		if scanner.Scan() {
			read = scanner.Text()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading from status pipe")
	}
	if read != line {
		t.Fatalf("read %q, want %q", read, line)
	}

	cleanup()

	if _, err := got.WriteString("after-cleanup\n"); err == nil {
		t.Fatal("expected write after cleanup() to fail (file closed), but it succeeded")
	}
}
