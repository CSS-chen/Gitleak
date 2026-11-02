package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gitleak/internal/gitx"
	"gitleak/internal/ui"
)

// FileRecord describes one restored file.
type FileRecord struct {
	Path  string `json:"path"`
	SHA1  string `json:"sha1"`
	Mode  string `json:"mode"`
	Bytes int    `json:"bytes"`
}

type symlinkTask struct {
	rel    string
	target string
}

type restorer struct {
	outDir   string
	ui       *ui.UI
	files    int
	bytes    int64
	failed   int
	records  []FileRecord
	warnings []string
	symlinks []symlinkTask
	seen     map[string]bool
	gitlinks []string
}

func newRestorer(outDir string, u *ui.UI) *restorer {
	return &restorer{outDir: outDir, ui: u, seen: make(map[string]bool)}
}

func (r *restorer) warn(format string, args ...any) {
	msg := format
	if len(args) > 0 {
		msg = sprintf(format, args...)
	}
	for _, w := range r.warnings {
		if w == msg {
			return
		}
	}
	r.warnings = append(r.warnings, msg)
	if r.ui != nil {
		r.ui.Warnf("%s", msg)
	}
}

func (r *restorer) Write(rel string, mode uint32, id gitx.ObjectID, data []byte) {
	clean, err := gitx.CleanIndexPath(rel)
	if err != nil {
		r.warn("skipping unsafe path %q: %v", rel, err)
		r.failed++
		return
	}
	if r.seen[clean] {
		return
	}
	r.seen[clean] = true
	switch {
	case gitx.ModeIsGitlink(mode):
		full := filepath.Join(r.outDir, filepath.FromSlash(clean))
		_ = os.MkdirAll(full, 0o755)
		r.gitlinks = append(r.gitlinks, clean)
		return
	case gitx.ModeIsSymlink(mode):
		r.symlinks = append(r.symlinks, symlinkTask{rel: clean, target: string(data)})
		r.records = append(r.records, FileRecord{Path: clean, SHA1: id.String(), Mode: "120000", Bytes: len(data)})
		return
	}
	r.writeRegular(clean, mode, id, data)
}

func (r *restorer) writeRegular(clean string, mode uint32, id gitx.ObjectID, data []byte) {
	rel := clean
	if runtime.GOOS == "windows" {
		if fixed, changed := safeWindowsPath(clean); changed {
			rel = fixed
			r.warn("path %q contains characters invalid on Windows, restored as %q", clean, fixed)
		}
	}
	full := filepath.Join(r.outDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.warn("cannot create directory for %q: %v", rel, err)
		r.failed++
		return
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		r.warn("cannot write %q: %v", rel, err)
		r.failed++
		return
	}
	if gitx.ModeIsExec(mode) && runtime.GOOS != "windows" {
		_ = os.Chmod(full, 0o755)
	}
	r.files++
	r.bytes += int64(len(data))
	r.records = append(r.records, FileRecord{Path: rel, SHA1: id.String(), Mode: gitx.ModeString(mode), Bytes: len(data)})
}

// Flush materialises pending symlinks last so that a hostile entry cannot make
// later writes traverse a symlink.
func (r *restorer) Flush() {
	for _, t := range r.symlinks {
		rel := t.rel
		if runtime.GOOS == "windows" {
			if fixed, changed := safeWindowsPath(rel); changed {
				rel = fixed
				r.warn("symlink path %q sanitised to %q", t.rel, fixed)
			}
		}
		full := filepath.Join(r.outDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			r.warn("cannot create directory for symlink %q: %v", rel, err)
			r.failed++
			continue
		}
		if err := os.Symlink(t.target, full); err != nil {
			if werr := os.WriteFile(full, []byte(t.target), 0o644); werr != nil {
				r.warn("cannot create symlink %q: %v", rel, err)
				r.failed++
				continue
			}
			r.warn("symlink %q could not be created (%v); wrote its target as a regular file", rel, err)
		}
		r.files++
		r.bytes += int64(len(t.target))
	}
	if len(r.gitlinks) > 0 {
		r.warn("%d submodule reference(s) were not fetched: %s", len(r.gitlinks), strings.Join(r.gitlinks, ", "))
	}
}

func safeWindowsPath(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	changed := false
	for i, p := range parts {
		np := safeWindowsComponent(p)
		if np != p {
			parts[i] = np
			changed = true
		}
	}
	return strings.Join(parts, "/"), changed
}

func safeWindowsComponent(s string) string {
	replacer := strings.NewReplacer("<", "_", ">", "_", ":", "_", "\"", "_", "|", "_", "?", "_", "*", "_")
	out := replacer.Replace(s)
	out = strings.TrimRight(out, " .")
	if out == "" {
		return "_"
	}
	base := out
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		base = base[:i]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return "_" + out
	}
	return out
}
