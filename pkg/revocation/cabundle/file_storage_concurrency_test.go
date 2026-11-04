package cabundle_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"github.com/agentic-research/signet/pkg/revocation/cabundle"
)

// PR #198 review: separate FileStorage instances (separate processes, in
// practice) on one directory shared nothing but the files. Two of them could
// both read 10, then persist 12 and then 11 -- a regression that keeps a
// valid HMAC -- and they shared a fixed ".tmp" name. The stored seqno must
// only ever be the max of what was offered.

const concurrencyKey = "test-hmac-key-32-bytes-long!!!!!"

func TestFileStorage_ConcurrentInstancesNeverRegress(t *testing.T) {
	for round := 0; round < 20; round++ {
		dir := t.TempDir()
		const writers, perWriter = 8, 25
		var wg sync.WaitGroup
		errs := make(chan error, writers*perWriter)
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				s, err := cabundle.NewFileStorage(dir, []byte(concurrencyKey))
				if err != nil {
					errs <- err
					return
				}
				r := rand.New(rand.NewSource(int64(round*100 + w)))
				for i := 0; i < perWriter; i++ {
					if err := s.SetLastSeenSeqnoIfGreater(context.Background(), "issuer", uint64(r.Intn(1000)+1)); err != nil {
						errs <- err
					}
				}
				// Every writer also offers the global max once.
				if err := s.SetLastSeenSeqnoIfGreater(context.Background(), "issuer", 5000); err != nil {
					errs <- err
				}
				for i := 0; i < perWriter; i++ {
					if err := s.SetLastSeenSeqnoIfGreater(context.Background(), "issuer", uint64(r.Intn(1000)+1)); err != nil {
						errs <- err
					}
				}
			}(w)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: concurrent write failed: %v", round, err)
		}
		s, _ := cabundle.NewFileStorage(dir, []byte(concurrencyKey))
		got, err := s.GetLastSeenSeqno(context.Background(), "issuer")
		if err != nil {
			t.Fatalf("round %d: read back: %v", round, err)
		}
		if got != 5000 {
			t.Fatalf("round %d: stored seqno %d, want the max 5000 (a lower write overwrote a higher one)", round, got)
		}
	}
}

// Same property across real processes: the test binary re-executes itself
// as writers.
func TestFileStorage_ConcurrentProcessesNeverRegress(t *testing.T) {
	if os.Getenv("SEQNO_WRITER_DIR") != "" {
		runSeqnoWriter(t)
		return
	}
	dir := t.TempDir()
	const procs = 6
	cmds := make([]*exec.Cmd, procs)
	for i := range cmds {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFileStorage_ConcurrentProcessesNeverRegress$")
		cmd.Env = append(os.Environ(), "SEQNO_WRITER_DIR="+dir, "SEQNO_WRITER_ID="+strconv.Itoa(i))
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = cmd
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	s, _ := cabundle.NewFileStorage(dir, []byte(concurrencyKey))
	got, err := s.GetLastSeenSeqno(context.Background(), "issuer")
	if err != nil {
		t.Fatal(err)
	}
	if got != 5000 {
		t.Fatalf("stored seqno %d across processes, want the max 5000", got)
	}
}

func runSeqnoWriter(t *testing.T) {
	id, _ := strconv.Atoi(os.Getenv("SEQNO_WRITER_ID"))
	s, err := cabundle.NewFileStorage(os.Getenv("SEQNO_WRITER_DIR"), []byte(concurrencyKey))
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(int64(id)))
	for i := 0; i < 200; i++ {
		v := uint64(r.Intn(1000) + 1)
		if i == 100 {
			v = 5000
		}
		if err := s.SetLastSeenSeqnoIfGreater(context.Background(), "issuer", v); err != nil {
			fmt.Fprintln(os.Stderr, err)
			t.Fatal(err)
		}
	}
}
