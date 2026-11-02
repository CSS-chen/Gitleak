package app

import (
	"bytes"
	"context"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitleak/internal/gitx"
	"gitleak/internal/httpc"
)

// Response size limits used during reconnaissance.
const (
	headMaxBody      = 1 << 20
	configMaxBody    = 4 << 20
	indexMaxBody     = 256 << 20
	logsMaxBody      = 32 << 20
	refsMaxBody      = 32 << 20
	infoPacksMaxBody = 1 << 20
)

var (
	headRE       = regexp.MustCompile("^(ref: refs/[A-Za-z0-9._/+-]+|[0-9a-f]{40})$")
	logsRE       = regexp.MustCompile("(?m)^[0-9a-f]{40} [0-9a-f]{40} .* <[^>]*> [0-9]+ [+-][0-9]{4}")
	packedRefsRE = regexp.MustCompile("(?m)^[0-9a-f]{40} refs/[^ ]+$")
	infoPacksRE  = regexp.MustCompile("(?m)^P (pack-[0-9a-f]{40}[.]pack)$")
	credURLRE    = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9+.-]*://[^/@ ]+:[^/@ ]+@")
)

// Detection is the result of probing one target for an exposed .git directory.
type Detection struct {
	Target     Target
	Vulnerable bool
	Score      int
	Evidence   []string
	Soft404    bool
	NetworkErr bool
	Elapsed    time.Duration
	Errors     []string

	HeadRaw    string
	HeadRef    string
	HeadObject string

	ConfigRaw   string
	RemoteURLs  []string
	RemoteCreds bool

	IndexOK   bool
	IndexRaw  []byte
	LogsOK    bool
	LogsRaw   string
	PackedOK  bool
	PackedRaw string
	PacksOK   bool
	PackNames []string

	Extras []string
}

// baselineCache stores the soft-404 probe result per target root.
type baselineCache struct {
	mu sync.Mutex
	m  map[string]*baseline
}

type baseline struct {
	status int
	soft   bool
}

func newBaselineCache() *baselineCache {
	return &baselineCache{m: make(map[string]*baseline)}
}

// NewBaselineCache creates the shared soft 404 probe cache used by Scan.
func NewBaselineCache() *baselineCache { return newBaselineCache() }

func (b *baselineCache) get(ctx context.Context, c *httpc.Client, root string) *baseline {
	b.mu.Lock()
	if v, ok := b.m[root]; ok {
		b.mu.Unlock()
		return v
	}
	b.mu.Unlock()
	token := strconv.FormatUint(rand.Uint64(), 16)
	resp, err := c.Get(ctx, root+"/.gitleak-"+token+".txt", headMaxBody)
	bl := &baseline{status: -1}
	if err == nil {
		bl.status = resp.StatusCode
		bl.soft = resp.StatusCode == 200
	}
	b.mu.Lock()
	b.m[root] = bl
	b.mu.Unlock()
	return bl
}

// Detect probes a target. When deep is set it also fetches the index, logs,
// packed refs and pack listing so a dump can reuse the data.
func Detect(ctx context.Context, c *httpc.Client, t Target, bc *baselineCache, deep bool) *Detection {
	start := time.Now()
	d := &Detection{Target: t}
	bl := bc.get(ctx, c, t.Root)
	d.Soft404 = bl.soft

	resp, err := c.Get(ctx, t.Probe("HEAD"), headMaxBody)
	if err != nil {
		d.NetworkErr = true
		d.Errors = append(d.Errors, "HEAD: "+err.Error())
	} else if resp.OK() {
		body := strings.TrimSpace(string(resp.Body))
		if headRE.MatchString(body) && len(body) < 256 {
			d.Vulnerable = true
			d.Score += 10
			d.HeadRaw = string(resp.Body)
			d.HeadRef, d.HeadObject = parseHead(body)
			d.Evidence = append(d.Evidence, "HEAD")
		}
	}

	if !d.Vulnerable && !d.NetworkErr {
		if cfg, err := c.Get(ctx, t.Probe("config"), configMaxBody); err == nil && cfg.OK() && validConfig(cfg.Body) {
			d.Vulnerable = true
			d.Score += 6
			d.ConfigRaw = string(cfg.Body)
			d.Evidence = append(d.Evidence, "config")
			d.RemoteURLs = configURLs(d.ConfigRaw)
			d.RemoteCreds = configHasCreds(d.RemoteURLs)
		}
	}
	if !d.Vulnerable {
		d.Elapsed = time.Since(start)
		return d
	}
	if d.ConfigRaw == "" {
		if cfg, err := c.Get(ctx, t.Probe("config"), configMaxBody); err == nil && cfg.OK() && validConfig(cfg.Body) {
			d.ConfigRaw = string(cfg.Body)
			d.Score++
			d.RemoteURLs = configURLs(d.ConfigRaw)
			d.RemoteCreds = configHasCreds(d.RemoteURLs)
		}
	}
	if deep {
		d.probeDeep(ctx, c)
	}
	d.Elapsed = time.Since(start)
	return d
}

func (d *Detection) probeDeep(ctx context.Context, c *httpc.Client) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	run := func(name string, maxBody int64) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(ctx, d.Target.Probe(name), maxBody)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				d.Errors = append(d.Errors, name+": "+err.Error())
				return
			}
			if !resp.OK() {
				return
			}
			switch name {
			case "index":
				if validIndex(resp.Body) {
					d.IndexOK = true
					d.IndexRaw = resp.Body
					d.Score += 5
					d.Evidence = append(d.Evidence, "index")
				}
			case "logs/HEAD":
				if logsRE.Match(resp.Body) {
					d.LogsOK = true
					d.LogsRaw = string(resp.Body)
					d.Score += 2
					d.Evidence = append(d.Evidence, "logs")
				}
			case "packed-refs":
				if bytes.HasPrefix(resp.Body, []byte("# pack-refs with:")) || packedRefsRE.Match(resp.Body) {
					d.PackedOK = true
					d.PackedRaw = string(resp.Body)
					d.Score += 2
					d.Evidence = append(d.Evidence, "packed-refs")
				}
			case "objects/info/packs":
				if names := parseInfoPacks(resp.Body); len(names) > 0 {
					d.PacksOK = true
					d.PackNames = names
					d.Score += 3
					d.Evidence = append(d.Evidence, "packs")
				}
			}
		}()
	}
	run("index", indexMaxBody)
	run("logs/HEAD", logsMaxBody)
	run("packed-refs", refsMaxBody)
	run("objects/info/packs", infoPacksMaxBody)
	wg.Wait()
}

// validHead reports whether a HEAD body looks like a real git HEAD file.
func validHead(body string) bool {
	b := strings.TrimSpace(body)
	return len(b) < 256 && headRE.MatchString(b)
}

func validConfig(body []byte) bool {
	if len(body) == 0 || len(body) > configMaxBody {
		return false
	}
	s := string(body)
	return strings.Contains(s, "[core]") && strings.Contains(s, "repositoryformatversion")
}

func validIndex(body []byte) bool {
	if len(body) < 32 || len(body) > indexMaxBody {
		return false
	}
	if string(body[:4]) != "DIRC" {
		return false
	}
	ver := uint32(body[4])<<24 | uint32(body[5])<<16 | uint32(body[6])<<8 | uint32(body[7])
	return ver >= 2 && ver <= 4
}

// configURLs extracts every remote url from a git config file.
func configURLs(s string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(strings.ToLower(key)) != "url" {
			continue
		}
		v := strings.TrimSpace(val)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func configHasCreds(urls []string) bool {
	for _, u := range urls {
		if credURLRE.MatchString(u) {
			return true
		}
	}
	return false
}

func parseInfoPacks(body []byte) []string {
	var names []string
	for _, m := range infoPacksRE.FindAllSubmatch(body, -1) {
		names = append(names, string(m[1]))
	}
	return names
}

// headRefName returns a short branch label such as "main".
func headRefName(ref string) string {
	if ref == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		return rest
	}
	return ref
}

// ObjectIDOf converts the detection HEAD object to a typed id.
func (d *Detection) ObjectIDOf() (gitx.ObjectID, bool) {
	if d.HeadObject == "" {
		return gitx.ObjectID{}, false
	}
	id, err := gitx.ParseObjectID(d.HeadObject)
	if err != nil {
		return gitx.ObjectID{}, false
	}
	return id, true
}

// extraProbePaths are legacy VCS / backup artefacts checked with --extra.
var extraProbePaths = []string{
	".svn/wc.db",
	".svn/entries",
	".hg/requires",
	".env",
	".DS_Store",
}

// DetectExtra probes common adjacent leaks. It is best effort.
func (d *Detection) DetectExtra(ctx context.Context, c *httpc.Client) {
	for _, p := range extraProbePaths {
		u := d.Target.Root + "/" + p
		resp, err := c.Get(ctx, u, 1<<20)
		if err != nil || !resp.OK() {
			continue
		}
		switch {
		case strings.HasSuffix(p, "wc.db") && bytes.HasPrefix(resp.Body, []byte("SQLite format 3")):
			d.Extras = append(d.Extras, "SVN working copy database exposed (.svn/wc.db)")
		case strings.HasSuffix(p, "entries") && bytes.Contains(resp.Body, []byte("dir\n")):
			d.Extras = append(d.Extras, "SVN metadata exposed (.svn/entries)")
		case strings.HasSuffix(p, "requires") && bytes.Contains(resp.Body, []byte("revlog")):
			d.Extras = append(d.Extras, "Mercurial repository exposed (.hg/requires)")
		case strings.HasSuffix(p, ".env") && bytes.Contains(resp.Body, []byte("=")):
			d.Extras = append(d.Extras, "dotenv file exposed (.env)")
		}
	}
}
