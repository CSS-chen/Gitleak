package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"gitleak/internal/gitx"
	"gitleak/internal/httpc"
	"gitleak/internal/ui"
)

// ErrObjectMissing means the object could not be obtained from anywhere.
var ErrObjectMissing = errors.New("git object not available on server")

const (
	maxRemoteObject     = 128 << 20
	maxObjectCacheBytes = 384 << 20
)

// objectFetcher retrieves git objects over HTTP (loose objects) and from a
// local packfile when one could be downloaded. It caches results and can keep
// a loose object store on disk for resumable runs.
type objectFetcher struct {
	client   *httpc.Client
	gitBase  string
	storeDir string
	ui       *ui.UI
	workers  int

	mu      sync.Mutex
	cache   map[gitx.ObjectID]gitx.Object
	invalid map[gitx.ObjectID]bool
	cacheB  atomic.Int64

	packMu   sync.Mutex
	pack     *gitx.PackFile
	packDesc string

	fetched  atomic.Int64
	hits     atomic.Int64
	missing  atomic.Int64
	failures atomic.Int64
}

func newObjectFetcher(c *httpc.Client, gitBase, storeDir string, u *ui.UI, workers int) *objectFetcher {
	if workers <= 0 {
		workers = 32
	}
	return &objectFetcher{
		client:   c,
		gitBase:  gitBase,
		storeDir: storeDir,
		ui:       u,
		workers:  workers,
		cache:    make(map[gitx.ObjectID]gitx.Object),
		invalid:  make(map[gitx.ObjectID]bool),
	}
}

// SetPack installs a downloaded packfile as the primary object source.
func (f *objectFetcher) SetPack(p *gitx.PackFile, desc string) {
	f.packMu.Lock()
	f.pack = p
	f.packDesc = desc
	f.packMu.Unlock()
}

// Pack returns the installed packfile, if any.
func (f *objectFetcher) Pack() *gitx.PackFile {
	f.packMu.Lock()
	defer f.packMu.Unlock()
	return f.pack
}

// Stats reports fetch counters.
func (f *objectFetcher) Stats() (fetched, cached, missing, failed int64) {
	return f.fetched.Load(), f.hits.Load(), f.missing.Load(), f.failures.Load()
}

func (f *objectFetcher) lookup(id gitx.ObjectID) (gitx.Object, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.cache[id]
	return obj, ok
}

func (f *objectFetcher) remember(id gitx.ObjectID, obj gitx.Object) {
	size := int64(len(obj.Data))
	if f.cacheB.Load()+size > maxObjectCacheBytes {
		return
	}
	f.mu.Lock()
	if _, exists := f.cache[id]; !exists {
		f.cache[id] = obj
		f.cacheB.Add(size)
	}
	f.mu.Unlock()
}

// Get returns one object, consulting cache, pack, local store and finally the
// remote loose object path.
func (f *objectFetcher) Get(ctx context.Context, id gitx.ObjectID) (gitx.Object, error) {
	if obj, ok := f.lookup(id); ok {
		f.hits.Add(1)
		return obj, nil
	}
	if p := f.Pack(); p != nil {
		if obj, err := p.Get(id); err == nil {
			f.hits.Add(1)
			f.remember(id, obj)
			return obj, nil
		}
	}
	if f.storeDir != "" {
		if obj, ok := f.readLocal(id); ok {
			f.hits.Add(1)
			f.remember(id, obj)
			return obj, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return gitx.Object{}, err
	}
	hexID := id.String()
	url := fmt.Sprintf("%s/objects/%s/%s", f.gitBase, hexID[:2], hexID[2:])
	resp, err := f.client.Get(ctx, url, maxRemoteObject)
	if err != nil {
		f.failures.Add(1)
		return gitx.Object{}, err
	}
	if resp.NotFound() || resp.StatusCode == 403 || resp.StatusCode == 401 {
		f.missing.Add(1)
		return gitx.Object{}, ErrObjectMissing
	}
	if !resp.OK() {
		f.failures.Add(1)
		return gitx.Object{}, fmt.Errorf("object %s: HTTP %d", hexID, resp.StatusCode)
	}
	typ, data, err := gitx.DecodeLooseObject(resp.Body)
	if err != nil {
		// A soft-404 HTML page or a corrupt object: retry from pack when
		// available, otherwise treat it as missing.
		if p := f.Pack(); p != nil {
			if obj, perr := p.Get(id); perr == nil {
				f.remember(id, obj)
				return obj, nil
			}
		}
		f.mu.Lock()
		f.invalid[id] = true
		f.mu.Unlock()
		f.missing.Add(1)
		return gitx.Object{}, fmt.Errorf("%w: %s: %v", ErrObjectMissing, hexID, err)
	}
	if got := gitx.HashObject(typ, data); got != id {
		f.failures.Add(1)
		return gitx.Object{}, fmt.Errorf("object %s: content hash mismatch (got %s)", hexID, got)
	}
	obj := gitx.Object{Type: typ, Data: data}
	f.remember(id, obj)
	f.fetched.Add(1)
	if f.storeDir != "" {
		f.writeLocal(id, resp.Body)
	}
	return obj, nil
}

// GetMany fetches ids concurrently, returning successful objects and the ids
// that could not be retrieved. Errors are not fatal unless the context dies.
func (f *objectFetcher) GetMany(ctx context.Context, ids []gitx.ObjectID) (map[gitx.ObjectID]gitx.Object, []gitx.ObjectID) {
	uniq := make([]gitx.ObjectID, 0, len(ids))
	seen := make(map[gitx.ObjectID]bool, len(ids))
	for _, id := range ids {
		if id.IsZero() || seen[id] {
			continue
		}
		seen[id] = true
		uniq = append(uniq, id)
	}
	results := make(map[gitx.ObjectID]gitx.Object, len(uniq))
	var mu sync.Mutex
	var missing []gitx.ObjectID
	var wg sync.WaitGroup
	jobs := make(chan gitx.ObjectID)
	workers := f.workers
	if workers > len(uniq) {
		workers = len(uniq)
	}
	if workers < 1 {
		return results, nil
	}
	var done atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				obj, err := f.Get(ctx, id)
				mu.Lock()
				if err != nil {
					missing = append(missing, id)
				} else {
					results[id] = obj
				}
				mu.Unlock()
				n := done.Add(1)
				if f.ui != nil && n%512 == 0 {
					f.ui.Progress("objects %d/%d", n, int64(len(uniq)))
				}
			}
		}()
	}
	for _, id := range uniq {
		select {
		case <-ctx.Done():
			break
		case jobs <- id:
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()
	if f.ui != nil && len(uniq) >= 512 {
		f.ui.ClearProgress()
	}
	return results, missing
}

func (f *objectFetcher) objectPath(id gitx.ObjectID) string {
	h := id.String()
	return filepath.Join(f.storeDir, h[:2], h[2:])
}

func (f *objectFetcher) readLocal(id gitx.ObjectID) (gitx.Object, bool) {
	raw, err := os.ReadFile(f.objectPath(id))
	if err != nil {
		return gitx.Object{}, false
	}
	typ, data, err := gitx.DecodeLooseObject(raw)
	if err != nil {
		return gitx.Object{}, false
	}
	if gitx.HashObject(typ, data) != id {
		return gitx.Object{}, false
	}
	return gitx.Object{Type: typ, Data: data}, true
}

func (f *objectFetcher) writeLocal(id gitx.ObjectID, raw []byte) {
	p := f.objectPath(id)
	if _, err := os.Stat(p); err == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
	}
}

// SaveObject writes an object into the on-disk loose store, useful when
// materialising a .git directory.
func (f *objectFetcher) SaveObject(id gitx.ObjectID, obj gitx.Object) error {
	if f.storeDir == "" {
		return nil
	}
	p := f.objectPath(id)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	raw, err := gitx.EncodeLooseObject(obj.Type, obj.Data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// multiResolver tries a pack first and falls back to the fetcher.
type multiResolver struct {
	pack  *gitx.PackFile
	fetch *objectFetcher
}

// Get implements gitx.Resolver.
func (m multiResolver) Get(id gitx.ObjectID) (gitx.Object, error) {
	if m.pack != nil {
		if obj, err := m.pack.Get(id); err == nil {
			return obj, nil
		}
	}
	if m.fetch != nil {
		return m.fetch.Get(context.Background(), id)
	}
	return gitx.Object{}, ErrObjectMissing
}
