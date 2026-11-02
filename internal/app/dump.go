package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gitleak/internal/gitx"
	"gitleak/internal/httpc"
	"gitleak/internal/ui"
)

// DumpOptions configures a reconstruction run.
type DumpOptions struct {
	OutRoot     string
	History     bool
	AllBranches bool
	WriteGit    bool
	Resume      bool
	Extract     bool
	ScanSecrets bool
	Extra       bool
	MaxPackMB   int
	MaxObjects  int
	Workers     int
}

// Dump reconstructs one exposed repository into OutRoot/<slug>.
func Dump(ctx context.Context, c *httpc.Client, det *Detection, opts DumpOptions, u *ui.UI) *TargetResult {
	start := time.Now()
	res := newTargetResult(det)
	if !det.Vulnerable {
		res.Error = "target does not expose a .git directory"
		res.ElapsedMS = time.Since(start).Milliseconds()
		return res
	}
	if opts.WriteGit {
		opts.History = true
	}
	if !opts.Extract {
		res.Warnings = append(res.Warnings, "detection only (--no-extract); nothing was downloaded")
		res.ElapsedMS = time.Since(start).Milliseconds()
		return res
	}
	t := det.Target
	outDir := filepath.Join(opts.OutRoot, t.Slug())
	res.OutDir = outDir
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		res.Error = "cannot create output directory: " + err.Error()
		res.ElapsedMS = time.Since(start).Milliseconds()
		return res
	}
	if u != nil {
		u.Infof("  target: %s", t.Root)
		u.Infof("  output: %s", outDir)
	}

	var gitDir string
	if opts.History || opts.WriteGit {
		gd, err := prepareGitDir(outDir, det)
		if err != nil {
			res.Warnings = append(res.Warnings, "cannot create .git skeleton: "+err.Error())
		} else {
			gitDir = gd
		}
	}
	storeDir := ""
	if gitDir != "" {
		storeDir = filepath.Join(gitDir, "objects")
	} else if opts.Resume {
		storeDir = filepath.Join(opts.OutRoot, ".gitleak-cache", t.Slug(), "objects")
	}
	fetcher := newObjectFetcher(c, t.Git, storeDir, u, maxInt(opts.Workers, 16))
	rest := newRestorer(outDir, u)

	historyDone := false
	var headID, stashID gitx.ObjectID
	if gitDir != "" && opts.History {
		historyDone, headID, stashID = runHistory(ctx, c, det, fetcher, gitDir, opts, u, res)
		if historyDone && !headID.IsZero() && res.HeadCommit == "" {
			res.HeadCommit = headID.String()
		}
	}

	// A packed repository serves its objects only through .pack files, so fetch
	// the pack even for a plain (non history) dump.
	if !historyDone && det.PacksOK {
		maxPack := int64(opts.MaxPackMB) << 20
		if maxPack <= 0 {
			maxPack = int64(1024) << 20
		}
		pi, warns, perr := downloadPack(ctx, c, det, gitDir, fetcher, u, maxPack)
		for _, w := range warns {
			res.Warnings = append(res.Warnings, w)
		}
		if perr != nil {
			res.Warnings = append(res.Warnings, "pack download failed: "+perr.Error())
		}
		if pi != nil {
			res.PackName = pi.name
			res.PackObjects = pi.objects
			res.PackBytes = pi.packLen
			if id, ref, herr := resolveHeadID(ctx, c, det); herr == nil {
				if obj, gerr := fetcher.Get(ctx, id); gerr == nil && obj.Type == gitx.TypeCommit {
					headID = id
					historyDone = true
					res.HeadCommit = id.String()
					if ref != "" {
						res.HeadRef = ref
					}
					if gitDir != "" {
						refs := parsePackedRefs(det.PackedRaw)
						if werr := writeGitMetadata(gitDir, det, id, ref, refs, opts.AllBranches); werr != nil {
							res.Warnings = append(res.Warnings, "cannot write refs: "+werr.Error())
						}
					}
				}
			}
			if u != nil {
				u.Goodf("downloaded pack %s (%d objects, %s)", pi.name, pi.objects, humanBytes(pi.packLen))
			}
		}
	}

	var missing []gitx.ObjectID
	var restoreErr error
	usedTree := false
	if historyDone && !headID.IsZero() {
		n, miss, err := restoreHeadTree(ctx, fetcher, headID, rest)
		missing = append(missing, miss...)
		if err == nil && n > 0 {
			usedTree = true
		} else if err != nil {
			res.Warnings = append(res.Warnings, "HEAD tree restore failed: "+err.Error())
		}
	}
	if !usedTree {
		n, miss, err := dumpViaIndex(ctx, c, det, fetcher, rest)
		missing = append(missing, miss...)
		if err == nil && n > 0 {
			_ = n
		} else {
			if err != nil {
				res.Warnings = append(res.Warnings, "index restore failed: "+err.Error())
			}
			n2, miss2, err2 := dumpViaHeadTree(ctx, c, det, fetcher, rest)
			missing = append(missing, miss2...)
			if err2 != nil {
				restoreErr = err2
			} else {
				_ = n2
				usedTree = true
			}
		}
	}
	rest.Flush()

	if gitDir != "" && opts.WriteGit {
		if _, raw, ierr := getIndex(ctx, c, det); ierr == nil && len(raw) > 0 {
			if werr := os.WriteFile(filepath.Join(gitDir, "index"), raw, 0o644); werr != nil {
				res.Warnings = append(res.Warnings, "cannot write git index: "+werr.Error())
			}
		} else if ierr != nil {
			res.Warnings = append(res.Warnings, "cannot write git index: "+ierr.Error())
		}
	}

	res.FilesRestored = rest.files
	res.Bytes = rest.bytes
	res.Files = rest.records
	if res.Files == nil {
		res.Files = []FileRecord{}
	}

	// A leaked refs/stash often holds files that are not on any branch; restore
	// that tree into a dedicated subdirectory so it cannot clash with HEAD.
	if !stashID.IsZero() {
		res.StashCommit = stashID.String()
		stashRoot := filepath.Join(outDir, ".gitleak-stash")
		srest := newRestorer(stashRoot, u)
		if n, _, serr := restoreHeadTree(ctx, fetcher, stashID, srest); serr != nil {
			res.Warnings = append(res.Warnings, "stash restore failed: "+serr.Error())
		} else {
			srest.Flush()
			res.StashFiles = n
			res.Bytes += srest.bytes
			for _, rec := range srest.records {
				rec.Path = ".gitleak-stash/" + rec.Path
				res.Files = append(res.Files, rec)
			}
			if n > 0 && u != nil {
				u.Goodf("recovered %d file(s) from refs/stash (%s) into .gitleak-stash/", n, humanBytes(srest.bytes))
			}
		}
	}
	res.Missing = idsToHex(missing)
	if res.Missing == nil {
		res.Missing = []string{}
	}
	for _, w := range rest.warnings {
		if !containsString(res.Warnings, w) {
			res.Warnings = append(res.Warnings, w)
		}
	}
	res.Score = det.Score
	if rest.files == 0 {
		if restoreErr != nil {
			res.Error = "reconstruction failed: " + restoreErr.Error()
		} else {
			res.Error = "no files could be recovered (index and HEAD objects unavailable)"
		}
	}
	if opts.ScanSecrets && rest.files > 0 {
		res.Secrets = scanSecrets(outDir, rest.records, u)
	}
	if res.HeadCommit == "" {
		if id, ref, herr := resolveHeadID(ctx, c, det); herr == nil && !id.IsZero() {
			res.HeadCommit = id.String()
			if res.HeadRef == "" {
				res.HeadRef = ref
			}
		}
	}
	res.ElapsedMS = time.Since(start).Milliseconds()
	if u != nil && rest.files > 0 {
		u.Goodf("restored %d files (%s) from %s", rest.files, humanBytes(rest.bytes), t.Root)
	}
	return res
}

// runHistory downloads full history either from a packfile or loose objects.
func runHistory(ctx context.Context, c *httpc.Client, det *Detection, fetcher *objectFetcher, gitDir string, opts DumpOptions, u *ui.UI, res *TargetResult) (bool, gitx.ObjectID, gitx.ObjectID) {
	maxPack := int64(opts.MaxPackMB) << 20
	if maxPack <= 0 {
		maxPack = int64(1024) << 20
	}
	if det.PacksOK {
		pi, warns, err := downloadPack(ctx, c, det, gitDir, fetcher, u, maxPack)
		for _, w := range warns {
			res.Warnings = append(res.Warnings, w)
		}
		if err != nil {
			res.Warnings = append(res.Warnings, "pack download failed: "+err.Error())
		}
		if pi != nil {
			refs := parsePackedRefs(det.PackedRaw)
			headID, headRef, herr := resolveHeadID(ctx, c, det)
			if herr == nil {
				if obj, gerr := fetcher.Get(ctx, headID); gerr == nil && obj.Type == gitx.TypeCommit {
					if err := writeGitMetadata(gitDir, det, headID, headRef, refs, opts.AllBranches); err != nil {
						res.Warnings = append(res.Warnings, "cannot write refs: "+err.Error())
					}
					stashID := gitx.ObjectID{}
					if sid, slog := resolveStash(ctx, c, det); !sid.IsZero() {
						if sobj, serr := fetcher.Get(ctx, sid); serr == nil && sobj.Type == gitx.TypeCommit {
							stashID = sid
							writeStashRefs(gitDir, sid, slog)
						}
					}
					res.PackName = pi.name
					res.PackObjects = pi.objects
					res.PackBytes = pi.packLen
					res.HeadCommit = headID.String()
					if headRef != "" {
						res.HeadRef = headRef
					}
					if u != nil {
						u.Goodf("downloaded pack %s (%d objects, %s)", pi.name, pi.objects, humanBytes(pi.packLen))
					}
					return true, headID, stashID
				}
			}
			res.Warnings = append(res.Warnings, "pack downloaded but HEAD commit is unreadable")
		}
	}
	stats, err := downloadLooseHistory(ctx, c, det, fetcher, gitDir, opts.MaxObjects, opts.AllBranches, u)
	if err != nil {
		res.Warnings = append(res.Warnings, "history walk failed: "+err.Error())
		return false, gitx.ObjectID{}, gitx.ObjectID{}
	}
	res.HistoryCommits = stats.commits
	res.HistoryObjects = stats.objects
	for _, w := range stats.warns {
		res.Warnings = append(res.Warnings, w)
	}
	if stats.missing > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d object(s) referenced by history are missing", stats.missing))
	}
	if stats.objects == 0 {
		return false, gitx.ObjectID{}, gitx.ObjectID{}
	}
	if u != nil {
		u.Goodf("recovered history: %d commits, %d objects (%s)", stats.commits, stats.objects, humanBytes(int64(stats.objects)))
	}
	return true, stats.headID, stats.stashID
}

func restoreHeadTree(ctx context.Context, f *objectFetcher, headID gitx.ObjectID, rest *restorer) (int, []gitx.ObjectID, error) {
	obj, err := f.Get(ctx, headID)
	if err != nil {
		return 0, nil, fmt.Errorf("cannot read HEAD commit: %w", err)
	}
	if obj.Type != gitx.TypeCommit {
		return 0, nil, fmt.Errorf("HEAD object is a %s, not a commit", obj.Type)
	}
	commit, err := gitx.ParseCommit(obj.Data)
	if err != nil {
		return 0, nil, err
	}
	return restoreTree(ctx, f, commit.Tree, rest)
}

func dumpViaIndex(ctx context.Context, c *httpc.Client, det *Detection, f *objectFetcher, rest *restorer) (int, []gitx.ObjectID, error) {
	entries, _, err := getIndex(ctx, c, det)
	if err != nil {
		return 0, nil, err
	}
	ids := make([]gitx.ObjectID, 0, len(entries))
	seen := make(map[gitx.ObjectID]bool, len(entries))
	usable := entries[:0]
	for _, e := range entries {
		if e.Stage != 0 || e.ID.IsZero() || gitx.ModeIsGitlink(e.Mode) {
			continue
		}
		usable = append(usable, e)
		if !seen[e.ID] {
			seen[e.ID] = true
			ids = append(ids, e.ID)
		}
	}
	objs, missing := f.GetMany(ctx, ids)
	for _, e := range usable {
		obj, ok := objs[e.ID]
		if !ok {
			continue
		}
		rest.Write(e.Path, e.Mode, e.ID, obj.Data)
	}
	return rest.files, missing, nil
}

func dumpViaHeadTree(ctx context.Context, c *httpc.Client, det *Detection, f *objectFetcher, rest *restorer) (int, []gitx.ObjectID, error) {
	headID, _, err := resolveHeadID(ctx, c, det)
	if err != nil {
		return 0, nil, err
	}
	before := rest.files
	_, missing, err := restoreHeadTree(ctx, f, headID, rest)
	if err != nil {
		return 0, missing, err
	}
	return rest.files - before, missing, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
