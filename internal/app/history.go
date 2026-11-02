package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitleak/internal/gitx"
	"gitleak/internal/httpc"
	"gitleak/internal/ui"
)

type logEntry struct {
	old string
	new string
}

func parseLogsHead(raw string) []logEntry {
	var out []logEntry
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields[0]) != 40 || len(fields[1]) != 40 {
			continue
		}
		out = append(out, logEntry{old: fields[0], new: fields[1]})
	}
	return out
}

func parsePackedRefs(raw string) map[string]string {
	refs := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && len(fields[0]) == 40 {
			refs[fields[1]] = strings.ToLower(fields[0])
		}
	}
	return refs
}

// resolveHeadID finds the commit HEAD points at using the ref file, the reflog
// and packed refs, in that order.
func resolveHeadID(ctx context.Context, c *httpc.Client, det *Detection) (gitx.ObjectID, string, error) {
	if id, ok := det.ObjectIDOf(); ok {
		return id, det.HeadRef, nil
	}
	ref := det.HeadRef
	if ref == "" {
		return gitx.ObjectID{}, "", errors.New("HEAD does not name a branch")
	}
	if resp, err := c.Get(ctx, det.Target.Probe(ref), 1<<20); err == nil && resp.OK() {
		if id, err := gitx.ParseObjectID(strings.TrimSpace(string(resp.Body))); err == nil {
			return id, ref, nil
		}
	}
	logsRaw := det.LogsRaw
	if logsRaw == "" {
		if resp, err := c.Get(ctx, det.Target.Probe("logs/HEAD"), logsMaxBody); err == nil && resp.OK() {
			logsRaw = string(resp.Body)
		}
	}
	if entries := parseLogsHead(logsRaw); len(entries) > 0 {
		if id, err := gitx.ParseObjectID(entries[len(entries)-1].new); err == nil {
			return id, ref, nil
		}
	}
	packedRaw := det.PackedRaw
	if packedRaw == "" {
		if resp, err := c.Get(ctx, det.Target.Probe("packed-refs"), refsMaxBody); err == nil && resp.OK() {
			packedRaw = string(resp.Body)
		}
	}
	if refs := parsePackedRefs(packedRaw); refs[ref] != "" {
		if id, err := gitx.ParseObjectID(refs[ref]); err == nil {
			return id, ref, nil
		}
	}
	return gitx.ObjectID{}, "", fmt.Errorf("cannot resolve %s to a commit", ref)
}

// resolveStash returns the leaked stash commit (refs/stash) and its reflog, if
// the target exposes them. Stash entries routinely hold data that is absent from
// every branch, so they are worth downloading even on a shallow dump.
func resolveStash(ctx context.Context, c *httpc.Client, det *Detection) (gitx.ObjectID, string) {
	resp, err := c.Get(ctx, det.Target.Probe("refs/stash"), refsMaxBody)
	if err != nil || !resp.OK() {
		return gitx.ObjectID{}, ""
	}
	id, perr := gitx.ParseObjectID(strings.TrimSpace(string(resp.Body)))
	if perr != nil {
		return gitx.ObjectID{}, ""
	}
	logText := ""
	if lr, lerr := c.Get(ctx, det.Target.Probe("logs/refs/stash"), refsMaxBody); lerr == nil && lr.OK() {
		logText = string(lr.Body)
	}
	return id, logText
}

// writeStashRefs materialises refs/stash and its reflog so that the recovered
// repository supports git stash list / git show refs/stash.
func writeStashRefs(gitDir string, id gitx.ObjectID, logText string) {
	refPath := filepath.Join(gitDir, "refs", "stash")
	if err := os.MkdirAll(filepath.Dir(refPath), 0o755); err == nil {
		_ = os.WriteFile(refPath, []byte(id.String()+"\n"), 0o644)
	}
	if strings.TrimSpace(logText) != "" {
		logPath := filepath.Join(gitDir, "logs", "refs", "stash")
		if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err == nil {
			_ = os.WriteFile(logPath, []byte(logText), 0o644)
		}
	}
}

type treeFile struct {
	path string
	mode uint32
	id   gitx.ObjectID
}

type treeNode struct {
	path string
	id   gitx.ObjectID
}

// walkTree walks a tree object breadth first and returns every non-directory
// entry. Missing subtrees are reported but do not abort the walk.
func walkTree(ctx context.Context, f *objectFetcher, root gitx.ObjectID, maxEntries int) ([]treeFile, []gitx.ObjectID, error) {
	files := make([]treeFile, 0, 256)
	var missing []gitx.ObjectID
	visited := make(map[gitx.ObjectID]bool)
	queue := []treeNode{{path: "", id: root}}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return files, missing, err
		}
		ids := make([]gitx.ObjectID, 0, len(queue))
		for _, n := range queue {
			if !visited[n.id] {
				visited[n.id] = true
				ids = append(ids, n.id)
			}
		}
		objs, miss := f.GetMany(ctx, ids)
		for _, id := range miss {
			missing = append(missing, id)
		}
		next := make([]treeNode, 0, len(queue))
		for _, n := range queue {
			obj, ok := objs[n.id]
			if !ok || obj.Type != gitx.TypeTree {
				continue
			}
			entries, err := gitx.ParseTree(obj.Data)
			if err != nil {
				continue
			}
			for _, e := range entries {
				full := e.Name
				if n.path != "" {
					full = n.path + "/" + e.Name
				}
				if e.Mode&gitx.ModeTypeMask == gitx.ModeDir {
					if !visited[e.ID] {
						next = append(next, treeNode{path: full, id: e.ID})
					}
					continue
				}
				files = append(files, treeFile{path: full, mode: e.Mode, id: e.ID})
				if len(files) > maxEntries {
					return files, missing, fmt.Errorf("tree contains more than %d entries", maxEntries)
				}
			}
		}
		queue = next
	}
	return files, missing, nil
}

// restoreTree downloads every blob of a tree and writes it to the output.
func restoreTree(ctx context.Context, f *objectFetcher, root gitx.ObjectID, rest *restorer) (int, []gitx.ObjectID, error) {
	files, missing, err := walkTree(ctx, f, root, 500000)
	if err != nil {
		return 0, missing, err
	}
	ids := make([]gitx.ObjectID, 0, len(files))
	seen := make(map[gitx.ObjectID]bool, len(files))
	for _, tf := range files {
		if gitx.ModeIsGitlink(tf.mode) {
			continue
		}
		if !seen[tf.id] {
			seen[tf.id] = true
			ids = append(ids, tf.id)
		}
	}
	objs, miss := f.GetMany(ctx, ids)
	missing = append(missing, miss...)
	restored := 0
	for _, tf := range files {
		if gitx.ModeIsGitlink(tf.mode) {
			rest.Write(tf.path, tf.mode, tf.id, nil)
			continue
		}
		obj, ok := objs[tf.id]
		if !ok {
			continue
		}
		rest.Write(tf.path, tf.mode, tf.id, obj.Data)
		restored++
	}
	return restored, missing, nil
}

// packInfo describes a downloaded packfile.
type packInfo struct {
	pack    *gitx.PackFile
	name    string
	objects int
	packLen int64
}

// downloadPack fetches objects/info/packs listed packfiles, storing them in the
// recovered .git directory.
func downloadPack(ctx context.Context, c *httpc.Client, det *Detection, gitDir string, f *objectFetcher, u *ui.UI, maxPackBytes int64) (*packInfo, []string, error) {
	var warns []string
	if !det.PacksOK || len(det.PackNames) == 0 {
		return nil, warns, nil
	}
	for _, name := range det.PackNames {
		base := strings.TrimSuffix(name, ".pack")
		idxURL := det.Target.Probe("objects/pack/" + base + ".idx")
		packURL := det.Target.Probe("objects/pack/" + name)
		if u != nil {
			u.Infof("  downloading pack index %s", base)
		}
		idxResp, err := c.Get(ctx, idxURL, 128<<20)
		if err != nil || !idxResp.OK() {
			warns = append(warns, fmt.Sprintf("pack index %s unavailable: %v", base, err))
			continue
		}
		idx, err := gitx.ParsePackIndex(idxResp.Body)
		if err != nil {
			warns = append(warns, fmt.Sprintf("pack index %s is invalid: %v", base, err))
			continue
		}
		if u != nil {
			u.Infof("  downloading pack %s (%d objects)", base, idx.Len())
		}
		packResp, err := c.Get(ctx, packURL, maxPackBytes)
		if err != nil {
			warns = append(warns, fmt.Sprintf("pack %s unavailable: %v", base, err))
			continue
		}
		if !packResp.OK() {
			warns = append(warns, fmt.Sprintf("pack %s returned HTTP %d", base, packResp.StatusCode))
			continue
		}
		pf, err := gitx.NewPackFile(idx, packResp.Body, multiResolver{fetch: f})
		if err != nil {
			warns = append(warns, fmt.Sprintf("pack %s is invalid: %v", base, err))
			continue
		}
		if gitDir != "" {
			packDir := filepath.Join(gitDir, "objects", "pack")
			if err := os.MkdirAll(packDir, 0o755); err == nil {
				_ = os.WriteFile(filepath.Join(packDir, base+".idx"), idxResp.Body, 0o644)
				_ = os.WriteFile(filepath.Join(packDir, name), packResp.Body, 0o644)
			}
		}
		f.SetPack(pf, base)
		return &packInfo{pack: pf, name: base, objects: idx.Len(), packLen: int64(len(packResp.Body))}, warns, nil
	}
	return nil, warns, nil
}

type historyStats struct {
	commits int
	trees   int
	blobs   int
	objects int
	missing int
	warns   []string

	headID   gitx.ObjectID
	headRef  string
	stashID  gitx.ObjectID
	stashLog string
}

// downloadLooseHistory walks commit/tree/blob objects reachable from the refs
// and stores them into the local object store.
func downloadLooseHistory(ctx context.Context, c *httpc.Client, det *Detection, f *objectFetcher, gitDir string, maxObjects int, allBranches bool, u *ui.UI) (*historyStats, error) {
	stats := &historyStats{}
	headID, headRef, err := resolveHeadID(ctx, c, det)
	if err != nil {
		return stats, err
	}
	if stashID, stashLog := resolveStash(ctx, c, det); !stashID.IsZero() {
		stats.stashID = stashID
		stats.stashLog = stashLog
	}
	refs := parsePackedRefs(det.PackedRaw)
	tips := []gitx.ObjectID{headID}
	if !stats.stashID.IsZero() {
		tips = append(tips, stats.stashID)
	}
	if allBranches {
		for _, sha := range refs {
			if id, err := gitx.ParseObjectID(sha); err == nil {
				tips = append(tips, id)
			}
		}
	}
	seen := make(map[gitx.ObjectID]bool)
	var blobIDs []gitx.ObjectID
	blobSeen := make(map[gitx.ObjectID]bool)
	treeQueue := make([]gitx.ObjectID, 0, 64)
	commitQueue := tips
	stop := false
	for len(commitQueue) > 0 && !stop {
		batch := make([]gitx.ObjectID, 0, len(commitQueue))
		var next []gitx.ObjectID
		for _, id := range commitQueue {
			if !seen[id] {
				seen[id] = true
				batch = append(batch, id)
			}
		}
		objs, miss := f.GetMany(ctx, batch)
		stats.missing += len(miss)
		for _, id := range batch {
			obj, ok := objs[id]
			if !ok {
				continue
			}
			stats.objects++
			switch obj.Type {
			case gitx.TypeCommit:
				cm, err := gitx.ParseCommit(obj.Data)
				if err != nil {
					continue
				}
				stats.commits++
				treeQueue = append(treeQueue, cm.Tree)
				for _, p := range cm.Parents {
					if !seen[p] {
						next = append(next, p)
					}
				}
			case gitx.TypeTag:
				tg, err := gitx.ParseTag(obj.Data)
				if err == nil && !seen[tg.Object] {
					next = append(next, tg.Object)
				}
			case gitx.TypeTree:
				treeQueue = append(treeQueue, id)
			}
			if maxObjects > 0 && stats.objects > maxObjects {
				stats.warns = append(stats.warns, fmt.Sprintf("history limited to %d objects", maxObjects))
				stop = true
			}
		}
		commitQueue = next
		if u != nil {
			u.Progress("history: %d objects", stats.objects)
		}
	}
	treeSeen := make(map[gitx.ObjectID]bool)
	for len(treeQueue) > 0 && !stop {
		batch := make([]gitx.ObjectID, 0, len(treeQueue))
		for _, id := range treeQueue {
			if !treeSeen[id] {
				treeSeen[id] = true
				batch = append(batch, id)
			}
		}
		treeQueue = nil
		objs, miss := f.GetMany(ctx, batch)
		stats.missing += len(miss)
		for _, id := range batch {
			obj, ok := objs[id]
			if !ok || obj.Type != gitx.TypeTree {
				continue
			}
			stats.trees++
			stats.objects++
			entries, err := gitx.ParseTree(obj.Data)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.Mode&gitx.ModeTypeMask == gitx.ModeDir {
					if !treeSeen[e.ID] {
						treeQueue = append(treeQueue, e.ID)
					}
					continue
				}
				if gitx.ModeIsGitlink(e.Mode) {
					continue
				}
				if !blobSeen[e.ID] {
					blobSeen[e.ID] = true
					blobIDs = append(blobIDs, e.ID)
				}
			}
			if maxObjects > 0 && stats.objects > maxObjects {
				stop = true
			}
		}
		if u != nil {
			u.Progress("history: %d objects", stats.objects)
		}
	}
	// Blobs are fetched in chunks to keep memory bounded.
	for start := 0; start < len(blobIDs) && !stop; start += 512 {
		end := start + 512
		if end > len(blobIDs) {
			end = len(blobIDs)
		}
		_, miss := f.GetMany(ctx, blobIDs[start:end])
		stats.missing += len(miss)
		stats.blobs += end - start - len(miss)
		stats.objects += end - start - len(miss)
		if u != nil {
			u.Progress("history: %d objects", stats.objects)
		}
		if maxObjects > 0 && stats.objects > maxObjects {
			stats.warns = append(stats.warns, fmt.Sprintf("history limited to %d objects", maxObjects))
			stop = true
		}
	}
	if u != nil {
		u.ClearProgress()
	}
	if gitDir != "" {
		if err := writeGitMetadata(gitDir, det, headID, headRef, refs, allBranches); err != nil {
			stats.warns = append(stats.warns, "cannot write git metadata: "+err.Error())
		}
		if !stats.stashID.IsZero() {
			writeStashRefs(gitDir, stats.stashID, stats.stashLog)
		}
	}
	stats.headID = headID
	stats.headRef = headRef
	return stats, nil
}

// prepareGitDir creates the skeleton of a git directory.
func prepareGitDir(outDir string, det *Detection) (string, error) {
	gitDir := filepath.Join(outDir, ".git")
	for _, d := range []string{"objects", "objects/pack", "objects/info", "refs/heads", "refs/tags"} {
		if err := os.MkdirAll(filepath.Join(gitDir, filepath.FromSlash(d)), 0o755); err != nil {
			return "", err
		}
	}
	head := "ref: refs/heads/master\n"
	if validHead(det.HeadRaw) {
		head = det.HeadRaw
		if !strings.HasSuffix(head, "\n") {
			head += "\n"
		}
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(head), 0o644); err != nil {
		return "", err
	}
	cfg := det.ConfigRaw
	if !validConfig([]byte(cfg)) {
		cfg = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(cfg), 0o644); err != nil {
		return "", err
	}
	desc := "Unnamed repository; edit this file to name the repository.\n"
	_ = os.WriteFile(filepath.Join(gitDir, "description"), []byte(desc), 0o644)
	return gitDir, nil
}

// writeGitMetadata writes refs and HEAD for a recovered repository.
func writeGitMetadata(gitDir string, det *Detection, headID gitx.ObjectID, headRef string, refs map[string]string, allBranches bool) error {
	if headRef == "" {
		headRef = "refs/heads/master"
	}
	if strings.HasPrefix(headRef, "refs/") {
		refs[headRef] = headID.String()
	}
	for name, sha := range refs {
		if !strings.HasPrefix(name, "refs/") || strings.Contains(name, "..") {
			continue
		}
		p := filepath.Join(gitDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			continue
		}
		_ = os.WriteFile(p, []byte(sha+"\n"), 0o644)
	}
	if !allBranches {
		// still keep any refs recovered from packed-refs; harmless
	}
	return nil
}

// getIndex returns parsed index entries, reusing detection data when present.
func getIndex(ctx context.Context, c *httpc.Client, det *Detection) ([]gitx.IndexEntry, []byte, error) {
	raw := det.IndexRaw
	if len(raw) == 0 {
		resp, err := c.Get(ctx, det.Target.Probe("index"), indexMaxBody)
		if err != nil {
			return nil, nil, err
		}
		if !resp.OK() || !validIndex(resp.Body) {
			return nil, nil, fmt.Errorf("index not available (HTTP %d)", resp.StatusCode)
		}
		raw = resp.Body
	}
	entries, err := gitx.ParseIndex(raw)
	if err != nil {
		return nil, raw, err
	}
	return entries, raw, nil
}
