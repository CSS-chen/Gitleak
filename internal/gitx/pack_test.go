package gitx

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file tests the pack reader against a pack produced by real git as well
// as against hand-built packs that exercise the delta encodings deterministically.

func TestMain(m *testing.M) {
	code := m.Run()
	packTestCleanupFixture()
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Fixture: a real git repository with a single aggressively repacked pack.
// ---------------------------------------------------------------------------

type packTestFixture struct {
	dir      string
	idxPath  string
	packPath string
	idxData  []byte
	packData []byte
	idx      *PackIndex
	expected map[ObjectID]Object
	deltas   int
}

var (
	packTestFixtureOnce sync.Once
	packTestFixtureData *packTestFixture
	packTestFixtureErr  error
)

func packTestFixtureGet(t *testing.T) *packTestFixture {
	t.Helper()
	packTestFixtureOnce.Do(func() {
		dir, err := packTestMkdirTemp()
		if err != nil {
			packTestFixtureErr = fmt.Errorf("create temporary directory: %w", err)
			return
		}
		fx := &packTestFixture{dir: dir}
		if err := packTestFixtureBuild(fx); err != nil {
			os.RemoveAll(dir)
			packTestFixtureErr = err
			return
		}
		packTestFixtureData = fx
	})
	if packTestFixtureErr != nil {
		t.Fatalf("pack test fixture: %v", packTestFixtureErr)
	}
	return packTestFixtureData
}

func packTestCleanupFixture() {
	if packTestFixtureData != nil {
		os.RemoveAll(packTestFixtureData.dir)
		packTestFixtureData = nil
	}
}

func packTestMkdirTemp() (string, error) {
	dir, err := os.MkdirTemp("", "gitleak-pack-test-")
	if err == nil {
		return dir, nil
	}
	// Fall back to a dot directory next to this package; the go tool ignores
	// directories whose names start with a dot.
	wd, wdErr := os.Getwd()
	if wdErr != nil {
		return "", err
	}
	return os.MkdirTemp(wd, ".packtest-")
}

func packTestFixtureBuild(fx *packTestFixture) error {
	dir := fx.dir
	if err := packTestGit(dir, "init", "-q"); err != nil {
		return err
	}
	for _, kv := range [][2]string{
		{"user.name", "Pack Test"},
		{"user.email", "pack@example.com"},
		{"core.autocrlf", "false"},
	} {
		if err := packTestGit(dir, "config", kv[0], kv[1]); err != nil {
			return err
		}
	}

	type testFile struct {
		name string
		gen  func(variant int) []byte
	}
	files := []testFile{
		{"big-pattern.txt", func(v int) []byte { return packTestPatterned(200*1024, v, "big") }},
		{"small-a.txt", func(v int) []byte { return packTestPatterned(20*1024, v, "alpha") }},
		{"small-b.txt", func(v int) []byte { return packTestPatterned(20*1024, v, "beta") }},
		{"small-c.txt", func(v int) []byte { return packTestPatterned(20*1024, v, "gamma") }},
		{"binary.bin", func(v int) []byte { return packTestBinary(8*1024, v) }},
	}
	for variant := 0; variant < 3; variant++ {
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f.name), f.gen(variant), 0o644); err != nil {
				return err
			}
		}
		if err := packTestGit(dir, "add", "-A"); err != nil {
			return err
		}
		if err := packTestGit(dir, "commit", "-q", "-m", fmt.Sprintf("fixture commit %d", variant)); err != nil {
			return err
		}
	}
	if err := packTestGit(dir, "branch", "feature"); err != nil {
		return err
	}
	if err := packTestGit(dir, "tag", "-a", "v1", "-m", "fixture release"); err != nil {
		return err
	}
	if err := packTestGit(dir, "gc", "--aggressive", "--prune=now", "--quiet"); err != nil {
		return err
	}

	matches, err := filepath.Glob(filepath.Join(dir, ".git", "objects", "pack", "*.idx"))
	if err != nil {
		return err
	}
	if len(matches) != 1 {
		return fmt.Errorf("expected exactly one pack index after gc, found %d", len(matches))
	}
	fx.idxPath = matches[0]
	fx.packPath = strings.TrimSuffix(fx.idxPath, ".idx") + ".pack"
	if fx.idxData, err = os.ReadFile(fx.idxPath); err != nil {
		return err
	}
	if fx.packData, err = os.ReadFile(fx.packPath); err != nil {
		return err
	}
	fx.idx, err = ParsePackIndex(fx.idxData)
	if err != nil {
		return fmt.Errorf("parse fixture index: %w", err)
	}
	ids := fx.idx.IDs()
	if len(ids) == 0 {
		return fmt.Errorf("fixture pack index is empty")
	}
	if fx.expected, err = packTestCatFileBatch(dir, ids); err != nil {
		return err
	}
	if len(fx.expected) != len(ids) {
		return fmt.Errorf("cat-file returned %d of %d objects", len(fx.expected), len(ids))
	}
	verify, err := packTestGitOutput(dir, "verify-pack", "-v", fx.idxPath)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(verify), "\n") {
		if len(strings.Fields(line)) == 7 {
			fx.deltas++
		}
	}
	if fx.deltas == 0 {
		return fmt.Errorf("fixture pack has no delta objects, delta decoding would be untested")
	}
	return nil
}

func packTestPatterned(size, variant int, salt string) []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < size; i++ {
		if i%500 == variant && variant > 0 {
			fmt.Fprintf(&b, "%08d: variant %d %s changed line that forces delta chains\n", i, variant, salt)
		} else {
			fmt.Fprintf(&b, "%08d: %s shared pack delta fixture corpus line %d of %d\n", i, salt, i, i%97)
		}
	}
	return b.Bytes()[:size]
}

func packTestBinary(size, variant int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte((i*31 + i/7) % 256)
	}
	b[0], b[1] = 0, 0
	if variant > 0 {
		copy(b[variant*100:], []byte{0, 0, 0, byte(variant), 0xff})
	}
	return b
}

func packTestGit(dir string, args ...string) error {
	_, err := packTestGitOutput(dir, args...)
	return err
}

func packTestGitOutput(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = packTestGitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return out, nil
}

func packTestGitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Pack Test",
		"GIT_AUTHOR_EMAIL=pack@example.com",
		"GIT_COMMITTER_NAME=Pack Test",
		"GIT_COMMITTER_EMAIL=pack@example.com",
		"GIT_AUTHOR_DATE=2021-01-02T03:04:05Z",
		"GIT_COMMITTER_DATE=2021-01-02T03:04:05Z",
	)
}

func packTestCatFileBatch(dir string, ids []ObjectID) (map[ObjectID]Object, error) {
	cmd := exec.Command("git", "cat-file", "--batch")
	cmd.Dir = dir
	cmd.Env = packTestGitEnv()
	var stdin bytes.Buffer
	for _, id := range ids {
		stdin.WriteString(id.String())
		stdin.WriteByte('\n')
	}
	cmd.Stdin = &stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git cat-file --batch: %w: %s", err, stderr.Bytes())
	}
	objs := make(map[ObjectID]Object, len(ids))
	pos := 0
	for i := 0; i < len(ids); i++ {
		nl := bytes.IndexByte(out[pos:], '\n')
		if nl < 0 {
			return nil, fmt.Errorf("cat-file --batch: truncated header for object %d", i)
		}
		header := string(out[pos : pos+nl])
		pos += nl + 1
		fields := strings.Fields(header)
		if len(fields) != 3 {
			return nil, fmt.Errorf("cat-file --batch: unexpected header %q", header)
		}
		id, err := ParseObjectID(fields[0])
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil || size < 0 {
			return nil, fmt.Errorf("cat-file --batch: bad size in %q", header)
		}
		if pos+size > len(out) {
			return nil, fmt.Errorf("cat-file --batch: truncated body for %s", id)
		}
		data := append([]byte(nil), out[pos:pos+size]...)
		pos += size
		if pos >= len(out) || out[pos] != '\n' {
			return nil, fmt.Errorf("cat-file --batch: missing body terminator for %s", id)
		}
		pos++
		objs[id] = Object{Type: fields[1], Data: data}
	}
	if pos != len(out) {
		return nil, fmt.Errorf("cat-file --batch: %d trailing bytes", len(out)-pos)
	}
	return objs, nil
}

// ---------------------------------------------------------------------------
// Index tests
// ---------------------------------------------------------------------------

func TestPackIndex(t *testing.T) {
	fx := packTestFixtureGet(t)
	idx := fx.idx
	if idx.Len() <= 0 {
		t.Fatalf("fixture index has %d objects", idx.Len())
	}
	wantCount := uint64(binary.BigEndian.Uint32(fx.packData[8:12]))
	if uint64(idx.Len()) != wantCount {
		t.Fatalf("index Len() = %d, pack header count = %d", idx.Len(), wantCount)
	}
	ids := idx.IDs()
	if len(ids) != idx.Len() {
		t.Fatalf("IDs() returned %d ids, Len() = %d", len(ids), idx.Len())
	}
	for i := 1; i < len(ids); i++ {
		if bytes.Compare(ids[i-1][:], ids[i][:]) >= 0 {
			t.Fatalf("ids are not strictly sorted at position %d", i)
		}
	}
	for _, id := range ids {
		off, ok := idx.Find(id)
		if !ok {
			t.Fatalf("Find(%s) = false", id)
		}
		off2, ok2 := idx.Offset(id)
		if !ok2 || off2 != off {
			t.Fatalf("Offset(%s) = (%d, %v), Find = (%d, %v)", id, off2, ok2, off, ok)
		}
	}
	var missing ObjectID
	for i := range missing {
		missing[i] = 0xFF
	}
	if _, ok := idx.Find(missing); ok {
		t.Fatal("Find reported an absent object id as present")
	}
	// IDs must return a defensive copy.
	cp := idx.IDs()
	cp[0] = ObjectID{}
	if idx.IDs()[0] != ids[0] {
		t.Fatal("IDs returned the internal slice")
	}
	// An empty v2 index parses to an empty index.
	var packSum [20]byte
	empty, err := ParsePackIndex(packTestBuildIdxV2Raw(nil, nil, nil, packSum))
	if err != nil {
		t.Fatalf("ParsePackIndex(empty): %v", err)
	}
	if empty.Len() != 0 {
		t.Fatalf("empty index Len() = %d", empty.Len())
	}
	var nilIdx *PackIndex
	if nilIdx.Len() != 0 {
		t.Fatal("nil index Len() != 0")
	}
	if _, ok := nilIdx.Find(missing); ok {
		t.Fatal("nil index Find reported a hit")
	}
}

func TestPackIndexV1(t *testing.T) {
	fx := packTestFixtureGet(t)
	ids := fx.idx.IDs()
	n := len(ids)
	if n == 0 {
		t.Fatal("fixture index is empty")
	}

	// Build a version 1 index out of the same data: fanout, then records of
	// 4 byte offset + 20 byte sha, then the same trailer.
	v1 := make([]byte, 0, idxFanoutSize+24*n+idxTrailerSize)
	v1 = append(v1, fx.idxData[8:8+idxFanoutSize]...)
	for _, id := range ids {
		off, ok := fx.idx.Offset(id)
		if !ok {
			t.Fatalf("Offset(%s) = false", id)
		}
		if off > 0x7fffffff {
			t.Fatalf("offset %d does not fit a version 1 index", off)
		}
		var b4 [4]byte
		binary.BigEndian.PutUint32(b4[:], uint32(off))
		v1 = append(v1, b4[:]...)
		v1 = append(v1, id[:]...)
	}
	v1 = append(v1, fx.idxData[len(fx.idxData)-idxTrailerSize:len(fx.idxData)-20]...)
	sum := sha1.Sum(v1)
	v1 = append(v1, sum[:]...)

	idx1, err := ParsePackIndex(v1)
	if err != nil {
		t.Fatalf("ParsePackIndex(v1): %v", err)
	}
	if idx1.Len() != n {
		t.Fatalf("v1 Len() = %d, want %d", idx1.Len(), n)
	}
	ids1 := idx1.IDs()
	for i := range ids {
		if ids1[i] != ids[i] {
			t.Fatalf("v1 id %d differs: %s != %s", i, ids1[i], ids[i])
		}
	}
	for _, id := range ids {
		want, _ := fx.idx.Offset(id)
		got, ok := idx1.Offset(id)
		if !ok || got != want {
			t.Fatalf("v1 Offset(%s) = (%d, %v), want (%d, true)", id, got, ok, want)
		}
	}
	pf, err := NewPackFile(idx1, fx.packData, nil)
	if err != nil {
		t.Fatalf("NewPackFile(v1): %v", err)
	}
	for _, id := range ids {
		obj, err := pf.Get(id)
		if err != nil {
			t.Fatalf("v1 Get(%s): %v", id, err)
		}
		want := fx.expected[id]
		if obj.Type != want.Type {
			t.Fatalf("v1 Get(%s) type = %q, want %q", id, obj.Type, want.Type)
		}
		if !bytes.Equal(obj.Data, want.Data) {
			t.Fatalf("v1 Get(%s) data mismatch (%d vs %d bytes)", id, len(obj.Data), len(want.Data))
		}
	}
	// Truncated version 1 indexes are rejected.
	for _, cut := range []int{0, 100, idxFanoutSize, idxFanoutSize + 23, len(v1) - 40, len(v1) - 1} {
		if cut < 0 || cut >= len(v1) {
			continue
		}
		if _, err := ParsePackIndex(v1[:cut]); err == nil {
			t.Fatalf("ParsePackIndex accepted a v1 index truncated to %d bytes", cut)
		}
	}
	// A corrupted checksum is rejected.
	bad := append([]byte(nil), v1...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := ParsePackIndex(bad); err == nil {
		t.Fatal("ParsePackIndex accepted a v1 index with a bad checksum")
	}
}

func TestPackIndexLargeOffsets(t *testing.T) {
	var idA, idB ObjectID
	idA[0] = 0x11
	idB[0] = 0x22
	ids := []ObjectID{idA, idB}
	// The second offset is encoded through the 8 byte large-offset table.
	idxBytes := packTestBuildIdxV2Raw(ids, []uint32{100, 0x80000000}, []uint64{5000}, [20]byte{})
	idx, err := ParsePackIndex(idxBytes)
	if err != nil {
		t.Fatalf("ParsePackIndex: %v", err)
	}
	if off, ok := idx.Offset(idA); !ok || off != 100 {
		t.Fatalf("Offset(idA) = (%d, %v), want (100, true)", off, ok)
	}
	if off, ok := idx.Offset(idB); !ok || off != 5000 {
		t.Fatalf("Offset(idB) = (%d, %v), want (5000, true)", off, ok)
	}
	// A large-offset index pointing past the table is rejected.
	badRaw := []uint32{100, 0x80000000 | 3}
	if _, err := ParsePackIndex(packTestBuildIdxV2Raw(ids, badRaw, []uint64{5000}, [20]byte{})); err == nil {
		t.Fatal("ParsePackIndex accepted an out of range large offset index")
	}
}

func TestParsePackIndexCorruption(t *testing.T) {
	fx := packTestFixtureGet(t)
	data := fx.idxData
	n := len(data)
	if n == 0 {
		t.Fatal("empty fixture index")
	}

	cuts := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 100, 1024, 1031, 1032, 1033, n / 4, n / 2, n - 41, n - 40, n - 21, n - 20, n - 1}
	for _, cut := range cuts {
		if cut < 0 || cut >= n {
			continue
		}
		cut := cut
		t.Run(fmt.Sprintf("truncate-%d", cut), func(t *testing.T) {
			if _, err := ParsePackIndex(data[:cut]); err == nil {
				t.Fatalf("ParsePackIndex accepted an index truncated to %d of %d bytes", cut, n)
			}
		})
	}

	flips := []int{0, 1, 3, 4, 7, 8, 9, 11, 1024, 1025, n / 2, n - 41, n - 21, n - 1}
	for _, at := range flips {
		if at < 0 || at >= n {
			continue
		}
		at := at
		t.Run(fmt.Sprintf("flip-%d", at), func(t *testing.T) {
			bad := append([]byte(nil), data...)
			bad[at] ^= 0xFF
			if _, err := ParsePackIndex(bad); err == nil {
				t.Fatalf("ParsePackIndex accepted an index with byte %d flipped", at)
			}
		})
	}

	garbage := [][]byte{nil, {}, []byte("junk"), []byte("PACK"), make([]byte, 1000), make([]byte, 5000)}
	for i, g := range garbage {
		g := g
		t.Run(fmt.Sprintf("garbage-%d", i), func(t *testing.T) {
			if _, err := ParsePackIndex(g); err == nil {
				t.Fatalf("ParsePackIndex accepted %d bytes of garbage", len(g))
			}
		})
	}

	// Structurally valid but with a wrong version; the checksum is fixed up so
	// only the version check can reject it.
	badVersion := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(badVersion[4:8], 3)
	badVersion = packTestResignIndex(badVersion)
	if _, err := ParsePackIndex(badVersion); err == nil {
		t.Fatal("ParsePackIndex accepted a version 3 index")
	}

	// Valid checksum but a broken fanout table.
	badFan := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(badFan[8:12], binary.BigEndian.Uint32(badFan[8:12])+1)
	badFan = packTestResignIndex(badFan)
	if _, err := ParsePackIndex(badFan); err == nil {
		t.Fatal("ParsePackIndex accepted an index with a corrupted fanout table")
	}

	// Valid checksum but unsorted object ids.
	badOrder := append([]byte(nil), data...)
	copy(badOrder[1032:1052], data[1052:1072])
	copy(badOrder[1052:1072], data[1032:1052])
	badOrder = packTestResignIndex(badOrder)
	if _, err := ParsePackIndex(badOrder); err == nil {
		t.Fatal("ParsePackIndex accepted unsorted object ids")
	}
}

// ---------------------------------------------------------------------------
// Pack file tests against real git output
// ---------------------------------------------------------------------------

func TestPackFileAllObjects(t *testing.T) {
	fx := packTestFixtureGet(t)
	if fx.deltas == 0 {
		t.Fatal("fixture pack has no deltas")
	}
	pf, err := NewPackFile(fx.idx, fx.packData, nil)
	if err != nil {
		t.Fatalf("NewPackFile: %v", err)
	}
	ids := fx.idx.IDs()
	if len(ids) == 0 {
		t.Fatal("fixture index is empty")
	}
	for _, id := range ids {
		want, ok := fx.expected[id]
		if !ok {
			t.Fatalf("no cat-file output recorded for %s", id)
		}
		obj, err := pf.Get(id)
		if err != nil {
			t.Fatalf("Get(%s): %v", id, err)
		}
		if obj.Type != want.Type {
			t.Fatalf("Get(%s) type = %q, want %q", id, obj.Type, want.Type)
		}
		if !bytes.Equal(obj.Data, want.Data) {
			t.Fatalf("Get(%s) data differs from git cat-file (%d vs %d bytes)", id, len(obj.Data), len(want.Data))
		}
		if got := HashObject(obj.Type, obj.Data); got != id {
			t.Fatalf("Get(%s) hashed to %s", id, got)
		}
		off, ok := fx.idx.Offset(id)
		if !ok {
			t.Fatalf("Offset(%s) = false", id)
		}
		byOff, err := pf.GetByOffset(off)
		if err != nil {
			t.Fatalf("GetByOffset(%d) for %s: %v", off, id, err)
		}
		if byOff.Type != want.Type || !bytes.Equal(byOff.Data, want.Data) {
			t.Fatalf("GetByOffset(%d) for %s differs from Get", off, id)
		}
	}
}

func TestPackFileConcurrent(t *testing.T) {
	fx := packTestFixtureGet(t)
	pf, err := NewPackFile(fx.idx, fx.packData, nil)
	if err != nil {
		t.Fatalf("NewPackFile: %v", err)
	}
	ids := fx.idx.IDs()
	if len(ids) == 0 {
		t.Fatal("fixture index is empty")
	}
	const goroutines = 8
	const iterations = 3
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				for _, id := range ids {
					obj, err := pf.Get(id)
					if err != nil {
						errCh <- fmt.Errorf("Get(%s): %w", id, err)
						return
					}
					want := fx.expected[id]
					if obj.Type != want.Type || !bytes.Equal(obj.Data, want.Data) {
						errCh <- fmt.Errorf("Get(%s) returned the wrong object", id)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestPackFileCorruption(t *testing.T) {
	fx := packTestFixtureGet(t)
	packData := fx.packData
	idx := fx.idx

	if _, err := NewPackFile(idx, packData, nil); err != nil {
		t.Fatalf("NewPackFile on a valid pack: %v", err)
	}
	if _, err := NewPackFile(nil, packData, nil); err == nil {
		t.Fatal("NewPackFile accepted a nil index")
	}

	// Object count mismatch.
	badCount := append([]byte(nil), packData...)
	count := binary.BigEndian.Uint32(badCount[8:12])
	binary.BigEndian.PutUint32(badCount[8:12], count+1)
	if _, err := NewPackFile(idx, badCount, nil); err == nil {
		t.Fatal("NewPackFile accepted a pack with an object count mismatch")
	}

	// Bad signature.
	badMagic := append([]byte(nil), packData...)
	badMagic[0] = 'X'
	if _, err := NewPackFile(idx, badMagic, nil); err == nil {
		t.Fatal("NewPackFile accepted a pack with a bad signature")
	}

	// Unsupported version.
	badVersion := append([]byte(nil), packData...)
	binary.BigEndian.PutUint32(badVersion[4:8], 1)
	if _, err := NewPackFile(idx, badVersion, nil); err == nil {
		t.Fatal("NewPackFile accepted pack version 1")
	}

	// Truncated headers.
	for _, cut := range []int{0, 4, 8, 11} {
		if _, err := NewPackFile(idx, packData[:cut], nil); err == nil {
			t.Fatalf("NewPackFile accepted a pack truncated to %d bytes", cut)
		}
	}

	// A truncated body: the header is fine, resolving the object is not.
	cut := len(packData) / 2
	var maxOff uint64
	var maxID ObjectID
	for _, id := range idx.IDs() {
		off, ok := idx.Offset(id)
		if !ok {
			t.Fatalf("Offset(%s) = false", id)
		}
		if off > maxOff {
			maxOff, maxID = off, id
		}
	}
	if maxOff < uint64(cut) {
		t.Fatalf("highest object offset %d is inside the truncated half (%d)", maxOff, cut)
	}
	truncatedPack, err := NewPackFile(idx, packData[:cut], nil)
	if err != nil {
		t.Fatalf("NewPackFile on a truncated pack: %v", err)
	}
	if _, err := packTestGetNoPanic(t, truncatedPack, maxID); err == nil {
		t.Fatalf("Get(%s) succeeded on a pack truncated to %d bytes", maxID, cut)
	}

	pf, err := NewPackFile(idx, packData, nil)
	if err != nil {
		t.Fatalf("NewPackFile: %v", err)
	}
	for _, off := range []uint64{0, 1, 5, 11, uint64(len(packData)), uint64(len(packData)) + 1, packMaxUint64} {
		if _, err := pf.GetByOffset(off); err == nil {
			t.Fatalf("GetByOffset(%d) succeeded", off)
		}
	}
	var missing ObjectID
	for i := range missing {
		missing[i] = 0xFF
	}
	if _, err := pf.Get(missing); err == nil {
		t.Fatal("Get succeeded for an object that is not in the pack")
	}
	var nilPack *PackFile
	if _, err := nilPack.Get(missing); err == nil {
		t.Fatal("nil PackFile Get succeeded")
	}
	if _, err := nilPack.GetByOffset(packHeaderLen); err == nil {
		t.Fatal("nil PackFile GetByOffset succeeded")
	}

	// Corrupted object entries must return an error or at least not reproduce
	// the original object; they must never panic.
	sampled := 0
	for _, id := range idx.IDs() {
		if sampled >= 6 {
			break
		}
		sampled++
		off, ok := idx.Offset(id)
		if !ok {
			t.Fatalf("Offset(%s) = false", id)
		}
		for _, extra := range []uint64{0, 1, 3} {
			at := off + extra
			if at >= uint64(len(packData)) {
				continue
			}
			bad := append([]byte(nil), packData...)
			bad[at] ^= 0xFF
			cpf, err := NewPackFile(idx, bad, nil)
			if err != nil {
				continue
			}
			obj, err := packTestGetNoPanic(t, cpf, id)
			if err == nil && HashObject(obj.Type, obj.Data) == id {
				t.Fatalf("corrupting byte %d of object %s still produced the original object", at, id)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Delta instruction tests (no repository needed)
// ---------------------------------------------------------------------------

func TestPackApplyDelta(t *testing.T) {
	put := packTestPutVarint
	base := []byte("abcdef")

	deltaCopy := put(nil, uint64(len(base)))
	deltaCopy = put(deltaCopy, 3)
	deltaCopy = append(deltaCopy, 0x91, 1, 3) // copy base[1:4]

	deltaInsert := put(nil, uint64(len(base)))
	deltaInsert = put(deltaInsert, 5)
	deltaInsert = append(deltaInsert, 0x05, 'x', 'y', 'z', 'w', 'q')

	bigBase := bytes.Repeat([]byte{'a'}, 0x10000)
	bigDelta := put(nil, uint64(len(bigBase)))
	bigDelta = put(bigDelta, uint64(len(bigBase)))
	bigDelta = append(bigDelta, 0x80) // copy, no offset/size bytes: size defaults to 0x10000

	// Explicit zero size byte after a copy opcode must also mean 0x10000.
	bigDeltaExplicitZero := put(nil, uint64(len(bigBase)))
	bigDeltaExplicitZero = put(bigDeltaExplicitZero, uint64(len(bigBase)))
	bigDeltaExplicitZero = append(bigDeltaExplicitZero, 0x90, 0x00)

	emptyResult := put(nil, 0)
	emptyResult = put(emptyResult, 0)

	opcodeZero := put(nil, uint64(len(base)))
	opcodeZero = put(opcodeZero, 0)
	opcodeZero = append(opcodeZero, 0x00)

	truncatedInsert := put(nil, uint64(len(base)))
	truncatedInsert = put(truncatedInsert, 5)
	truncatedInsert = append(truncatedInsert, 0x05, 'a')

	copyRange := put(nil, uint64(len(base)))
	copyRange = put(copyRange, 3)
	copyRange = append(copyRange, 0x91, 4, 3)

	resultShort := put(nil, uint64(len(base)))
	resultShort = put(resultShort, 5)
	resultShort = append(resultShort, 0x01, 'a')

	baseMismatch := put(nil, uint64(len(base))+1)
	baseMismatch = put(baseMismatch, 0)

	resultHuge := put(nil, uint64(len(base)))
	resultHuge = put(resultHuge, uint64(maxPackObjectSize)+1)

	insertOverrun := put(nil, uint64(len(base)))
	insertOverrun = put(insertOverrun, 1)
	insertOverrun = append(insertOverrun, 0x02, 'a', 'b')

	tests := []struct {
		name    string
		base    []byte
		delta   []byte
		want    []byte
		wantErr bool
	}{
		{name: "copy", base: base, delta: deltaCopy, want: []byte("bcd")},
		{name: "insert", base: base, delta: deltaInsert, want: []byte("xyzwq")},
		{name: "copy-size-zero-means-0x10000", base: bigBase, delta: bigDelta, want: bigBase},
		{name: "copy-explicit-zero-size-byte", base: bigBase, delta: bigDeltaExplicitZero, want: bigBase},
		{name: "empty-result", base: []byte{}, delta: emptyResult, want: []byte{}},
		{name: "opcode-zero", base: base, delta: opcodeZero, wantErr: true},
		{name: "truncated-insert", base: base, delta: truncatedInsert, wantErr: true},
		{name: "copy-out-of-range", base: base, delta: copyRange, wantErr: true},
		{name: "result-shorter-than-declared", base: base, delta: resultShort, wantErr: true},
		{name: "base-size-mismatch", base: base, delta: baseMismatch, wantErr: true},
		{name: "result-too-large", base: base, delta: resultHuge, wantErr: true},
		{name: "insert-overruns-result", base: base, delta: insertOverrun, wantErr: true},
		{name: "varint-overflow", base: base, delta: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, wantErr: true},
		{name: "truncated-header", base: base, delta: []byte{0x80}, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := packApplyDelta(tc.base, tc.delta)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("packApplyDelta succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("packApplyDelta: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("packApplyDelta = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Hand-built pack tests
// ---------------------------------------------------------------------------

func TestPackRefDelta(t *testing.T) {
	baseData := []byte("hello world\n")
	resultData := []byte("world\nhello\n")
	baseID := HashObject(TypeBlob, baseData)
	resultID := HashObject(TypeBlob, resultData)

	delta := packTestPutVarint(nil, uint64(len(baseData)))
	delta = packTestPutVarint(delta, uint64(len(resultData)))
	delta = append(delta, 0x91, 6, 6) // copy base[6:12]  => "world\n"
	delta = append(delta, 0x91, 0, 5) // copy base[0:5]   => "hello"
	delta = append(delta, 0x01, '\n') // insert newline

	t.Run("in-pack-base", func(t *testing.T) {
		entries := []packTestEntry{
			{id: baseID, raw: packTestBaseEntry(baseData)},
			{id: resultID, raw: packTestRefDeltaEntry(baseID, delta)},
		}
		packData, offsets := packTestAssemble(entries)
		idxBytes := packTestBuildIdx(entries, offsets, packData)
		idx, err := ParsePackIndex(idxBytes)
		if err != nil {
			t.Fatalf("ParsePackIndex: %v", err)
		}
		if idx.Len() != 2 {
			t.Fatalf("index Len() = %d, want 2", idx.Len())
		}
		pf, err := NewPackFile(idx, packData, nil)
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		packTestCompareObjects(t, pf, baseID, Object{Type: TypeBlob, Data: baseData})
		packTestCompareObjects(t, pf, resultID, Object{Type: TypeBlob, Data: resultData})
	})

	t.Run("external-base", func(t *testing.T) {
		entries := []packTestEntry{{id: resultID, raw: packTestRefDeltaEntry(baseID, delta)}}
		packData, offsets := packTestAssemble(entries)
		idx, err := ParsePackIndex(packTestBuildIdx(entries, offsets, packData))
		if err != nil {
			t.Fatalf("ParsePackIndex: %v", err)
		}
		noBase, err := NewPackFile(idx, packData, nil)
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		if _, err := noBase.Get(resultID); err == nil {
			t.Fatal("Get succeeded although the REF_DELTA base is unavailable")
		}
		withBase, err := NewPackFile(idx, packData, &packTestResolver{objs: map[ObjectID]Object{
			baseID: {Type: TypeBlob, Data: baseData},
		}})
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		packTestCompareObjects(t, withBase, resultID, Object{Type: TypeBlob, Data: resultData})
		failing, err := NewPackFile(idx, packData, &packTestResolver{err: errors.New("resolver exploded")})
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		if _, err := failing.Get(resultID); err == nil {
			t.Fatal("Get ignored a failing base resolver")
		}
	})
}

func TestPackOFSDelta(t *testing.T) {
	baseData := bytes.Repeat([]byte("0123456789abcdef"), 64) // 1024 bytes
	baseID := HashObject(TypeBlob, baseData)

	// First delta: base[100:200] followed by base[500:600].
	delta1 := packTestPutVarint(nil, uint64(len(baseData)))
	delta1 = packTestPutVarint(delta1, 200)
	delta1 = append(delta1, 0x91, 100, 100)        // copy base[100:200]
	delta1 = append(delta1, 0x93, 0xF4, 0x01, 100) // copy base[500:600]
	result1 := append(append([]byte{}, baseData[100:200]...), baseData[500:600]...)
	result1ID := HashObject(TypeBlob, result1)

	baseEntry := packTestBaseEntry(baseData)
	baseOff := uint64(packHeaderLen)
	delta1Off := baseOff + uint64(len(baseEntry))
	entry1 := packTestOFSDeltaEntry(baseOff, delta1Off, delta1)

	// Second delta: delta1's object[0:50], chained on top of the first delta.
	delta2 := packTestPutVarint(nil, uint64(len(result1)))
	delta2 = packTestPutVarint(delta2, 50)
	delta2 = append(delta2, 0x91, 0, 50) // copy result1[0:50]
	result2 := append([]byte{}, result1[0:50]...)
	result2ID := HashObject(TypeBlob, result2)
	entry2Off := delta1Off + uint64(len(entry1))
	entry2 := packTestOFSDeltaEntry(delta1Off, entry2Off, delta2)

	entries := []packTestEntry{
		{id: baseID, raw: baseEntry},
		{id: result1ID, raw: entry1},
		{id: result2ID, raw: entry2},
	}
	packData, offsets := packTestAssemble(entries)
	if offsets[0] != baseOff || offsets[1] != delta1Off || offsets[2] != entry2Off {
		t.Fatalf("unexpected pack offsets %v", offsets)
	}
	idx, err := ParsePackIndex(packTestBuildIdx(entries, offsets, packData))
	if err != nil {
		t.Fatalf("ParsePackIndex: %v", err)
	}
	pf, err := NewPackFile(idx, packData, nil)
	if err != nil {
		t.Fatalf("NewPackFile: %v", err)
	}
	packTestCompareObjects(t, pf, baseID, Object{Type: TypeBlob, Data: baseData})
	packTestCompareObjects(t, pf, result1ID, Object{Type: TypeBlob, Data: result1})
	packTestCompareObjects(t, pf, result2ID, Object{Type: TypeBlob, Data: result2})
}

func TestPackEdgeCases(t *testing.T) {
	t.Run("empty-pack", func(t *testing.T) {
		packData, offsets := packTestAssemble(nil)
		if len(offsets) != 0 {
			t.Fatalf("assembled %d offsets for an empty pack", len(offsets))
		}
		idx, err := ParsePackIndex(packTestBuildIdx(nil, nil, packData))
		if err != nil {
			t.Fatalf("ParsePackIndex: %v", err)
		}
		if idx.Len() != 0 {
			t.Fatalf("empty index Len() = %d", idx.Len())
		}
		pf, err := NewPackFile(idx, packData, nil)
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		var id ObjectID
		if _, err := pf.Get(id); err == nil {
			t.Fatal("Get succeeded on an empty pack")
		}
		if _, err := pf.GetByOffset(packHeaderLen); err == nil {
			t.Fatal("GetByOffset succeeded on an empty pack")
		}
		if _, err := pf.GetByOffset(packMaxUint64); err == nil {
			t.Fatal("GetByOffset(MaxUint64) succeeded on an empty pack")
		}
	})

	t.Run("unknown-object-type", func(t *testing.T) {
		var id ObjectID
		id[0] = 0x42
		raw := append(packTestEntryHeader(5, 4), packTestZlib([]byte("abcd"))...)
		entries := []packTestEntry{{id: id, raw: raw}}
		packData, offsets := packTestAssemble(entries)
		idx, err := ParsePackIndex(packTestBuildIdx(entries, offsets, packData))
		if err != nil {
			t.Fatalf("ParsePackIndex: %v", err)
		}
		pf, err := NewPackFile(idx, packData, nil)
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		if _, err := pf.Get(id); err == nil {
			t.Fatal("Get accepted an unknown object type")
		}
	})

	t.Run("oversized-header", func(t *testing.T) {
		var id ObjectID
		id[0] = 0x43
		raw := packTestEntryHeader(packTypeBlob, maxPackObjectSize+1)
		entries := []packTestEntry{{id: id, raw: raw}}
		packData, offsets := packTestAssemble(entries)
		idx, err := ParsePackIndex(packTestBuildIdx(entries, offsets, packData))
		if err != nil {
			t.Fatalf("ParsePackIndex: %v", err)
		}
		pf, err := NewPackFile(idx, packData, nil)
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		if _, err := pf.Get(id); err == nil {
			t.Fatal("Get accepted an object larger than the size cap")
		}
	})

	t.Run("ref-delta-cycle", func(t *testing.T) {
		var idA, idB ObjectID
		idA[0] = 0x10
		idB[0] = 0x20
		emptyDelta := packTestPutVarint(packTestPutVarint(nil, 0), 0)
		// Two entries whose REF_DELTA bases reference each other.
		entryA := packTestRefDeltaEntry(idB, emptyDelta)
		entryB := packTestRefDeltaEntry(idA, emptyDelta)
		entries := []packTestEntry{{id: idA, raw: entryA}, {id: idB, raw: entryB}}
		packData, offsets := packTestAssemble(entries)
		idx, err := ParsePackIndex(packTestBuildIdx(entries, offsets, packData))
		if err != nil {
			t.Fatalf("ParsePackIndex: %v", err)
		}
		pf, err := NewPackFile(idx, packData, nil)
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		if _, err := packTestGetWithTimeout(t, pf, idA); err == nil {
			t.Fatal("Get accepted a delta cycle")
		}
	})

	t.Run("ref-delta-self-reference", func(t *testing.T) {
		var id ObjectID
		id[0] = 0x30
		emptyDelta := packTestPutVarint(packTestPutVarint(nil, 0), 0)
		entries := []packTestEntry{{id: id, raw: packTestRefDeltaEntry(id, emptyDelta)}}
		packData, offsets := packTestAssemble(entries)
		idx, err := ParsePackIndex(packTestBuildIdx(entries, offsets, packData))
		if err != nil {
			t.Fatalf("ParsePackIndex: %v", err)
		}
		pf, err := NewPackFile(idx, packData, nil)
		if err != nil {
			t.Fatalf("NewPackFile: %v", err)
		}
		if _, err := packTestGetWithTimeout(t, pf, id); err == nil {
			t.Fatal("Get accepted a self-referencing delta")
		}
	})
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type packTestResolver struct {
	objs map[ObjectID]Object
	err  error
}

func (r *packTestResolver) Get(id ObjectID) (Object, error) {
	if r.err != nil {
		return Object{}, r.err
	}
	obj, ok := r.objs[id]
	if !ok {
		return Object{}, fmt.Errorf("%w: %s", errPackObjectNotFound, id)
	}
	return obj, nil
}

func packTestCompareObjects(t *testing.T, pf *PackFile, id ObjectID, want Object) {
	t.Helper()
	got, err := pf.Get(id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	if got.Type != want.Type {
		t.Fatalf("Get(%s) type = %q, want %q", id, got.Type, want.Type)
	}
	if !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("Get(%s) data = %q, want %q", id, got.Data, want.Data)
	}
	if h := HashObject(got.Type, got.Data); h != id {
		t.Fatalf("Get(%s) hashed to %s", id, h)
	}
}

func packTestGetNoPanic(t *testing.T, pf *PackFile, id ObjectID) (obj Object, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Get(%s) panicked: %v", id, r)
		}
	}()
	return pf.Get(id)
}

func packTestGetWithTimeout(t *testing.T, pf *PackFile, id ObjectID) (Object, error) {
	t.Helper()
	type outcome struct {
		obj Object
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		obj, err := pf.Get(id)
		ch <- outcome{obj, err}
	}()
	select {
	case o := <-ch:
		return o.obj, o.err
	case <-time.After(10 * time.Second):
		t.Fatalf("Get(%s) did not return within 10s, likely a deadlock", id)
		return Object{}, nil
	}
}

func packTestResignIndex(data []byte) []byte {
	out := append([]byte(nil), data...)
	sum := sha1.Sum(out[:len(out)-20])
	copy(out[len(out)-20:], sum[:])
	return out
}

// ---------------------------------------------------------------------------
// Synthetic pack construction helpers
// ---------------------------------------------------------------------------

type packTestEntry struct {
	id  ObjectID
	raw []byte
}

// packTestAssemble builds a version 2 pack file out of raw object entries and
// returns the pack bytes plus each entry's offset.
func packTestAssemble(entries []packTestEntry) ([]byte, []uint64) {
	var buf bytes.Buffer
	buf.WriteString("PACK")
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], 2)
	buf.Write(b4[:])
	binary.BigEndian.PutUint32(b4[:], uint32(len(entries)))
	buf.Write(b4[:])
	offsets := make([]uint64, len(entries))
	for i, e := range entries {
		offsets[i] = uint64(buf.Len())
		buf.Write(e.raw)
	}
	sum := sha1.Sum(buf.Bytes())
	buf.Write(sum[:])
	return buf.Bytes(), offsets
}

// packTestEntryHeader encodes the object type and decoded size header.
func packTestEntryHeader(typ byte, size int) []byte {
	var hdr []byte
	c := byte(typ<<4) | byte(size&0x0f)
	size >>= 4
	for size != 0 {
		hdr = append(hdr, c|0x80)
		c = byte(size & 0x7f)
		size >>= 7
	}
	return append(hdr, c)
}

func packTestZlib(data []byte) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func packTestBaseEntry(data []byte) []byte {
	return append(packTestEntryHeader(packTypeBlob, len(data)), packTestZlib(data)...)
}

func packTestRefDeltaEntry(baseID ObjectID, delta []byte) []byte {
	out := packTestEntryHeader(packTypeREFDelta, len(delta))
	out = append(out, baseID[:]...)
	return append(out, packTestZlib(delta)...)
}

func packTestOFSDeltaEntry(baseOff, curOff uint64, delta []byte) []byte {
	out := packTestEntryHeader(packTypeOFSDelta, len(delta))
	out = append(out, packTestEncodeOFSDistance(baseOff, curOff)...)
	return append(out, packTestZlib(delta)...)
}

// packTestEncodeOFSDistance encodes the negative relative distance used by an
// OFS_DELTA entry.
func packTestEncodeOFSDistance(baseOff, curOff uint64) []byte {
	ofs := curOff - baseOff
	var buf [10]byte
	i := len(buf)
	buf[i-1] = byte(ofs & 0x7f)
	i--
	for ofs >>= 7; ofs != 0; ofs >>= 7 {
		i--
		buf[i] = byte((ofs-1)&0x7f) | 0x80
	}
	return append([]byte(nil), buf[i:]...)
}

func packTestBuildIdx(entries []packTestEntry, offsets []uint64, packData []byte) []byte {
	type pair struct {
		id  ObjectID
		off uint64
	}
	pairs := make([]pair, len(entries))
	for i, e := range entries {
		pairs[i] = pair{id: e.id, off: offsets[i]}
	}
	sort.Slice(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].id[:], pairs[j].id[:]) < 0
	})
	ids := make([]ObjectID, len(pairs))
	var raw []uint32
	var large []uint64
	for i, p := range pairs {
		ids[i] = p.id
		if p.off > 0x7fffffff {
			raw = append(raw, 0x80000000|uint32(len(large)))
			large = append(large, p.off)
		} else {
			raw = append(raw, uint32(p.off))
		}
	}
	packSum := sha1.Sum(packData[:len(packData)-20])
	return packTestBuildIdxV2Raw(ids, raw, large, packSum)
}

// packTestBuildIdxV2Raw assembles a version 2 index from pre-encoded offsets.
// ids must be sorted strictly ascending.
func packTestBuildIdxV2Raw(ids []ObjectID, raw []uint32, large []uint64, packSum [20]byte) []byte {
	var buf bytes.Buffer
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], idxMagic)
	buf.Write(b4[:])
	binary.BigEndian.PutUint32(b4[:], 2)
	buf.Write(b4[:])
	var hist [256]uint32
	for _, id := range ids {
		hist[id[0]]++
	}
	var running uint32
	for i := 0; i < 256; i++ {
		running += hist[i]
		binary.BigEndian.PutUint32(b4[:], running)
		buf.Write(b4[:])
	}
	for _, id := range ids {
		buf.Write(id[:])
	}
	buf.Write(make([]byte, 4*len(ids))) // CRC table; this reader does not use it
	for _, r := range raw {
		binary.BigEndian.PutUint32(b4[:], r)
		buf.Write(b4[:])
	}
	for _, l := range large {
		var b8 [8]byte
		binary.BigEndian.PutUint64(b8[:], l)
		buf.Write(b8[:])
	}
	buf.Write(packSum[:])
	sum := sha1.Sum(buf.Bytes())
	buf.Write(sum[:])
	return buf.Bytes()
}

func packTestPutVarint(dst []byte, v uint64) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			dst = append(dst, b|0x80)
			continue
		}
		return append(dst, b)
	}
}
