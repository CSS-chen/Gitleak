package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gitleak/internal/gitx"
)

// Version is the tool version reported by the CLI and JSON output.
const Version = "1.1.0"

// SecretFinding is a credential-looking string found in restored files.
type SecretFinding struct {
	Path  string `json:"path"`
	Kind  string `json:"kind"`
	Match string `json:"match"`
}

// TargetResult is the per target outcome written to the JSON report.
type TargetResult struct {
	Input          string          `json:"input"`
	Root           string          `json:"root"`
	Vulnerable     bool            `json:"vulnerable"`
	Score          int             `json:"score"`
	Soft404        bool            `json:"soft_404"`
	HeadRef        string          `json:"head_ref"`
	HeadCommit     string          `json:"head_commit"`
	Remote         string          `json:"remote"`
	RemoteCreds    bool            `json:"remote_credentials"`
	Evidence       []string        `json:"evidence"`
	FilesRestored  int             `json:"files_restored"`
	Bytes          int64           `json:"bytes"`
	OutDir         string          `json:"out_dir"`
	PackName       string          `json:"pack,omitempty"`
	PackObjects    int             `json:"pack_objects,omitempty"`
	PackBytes      int64           `json:"pack_bytes,omitempty"`
	HistoryCommits int             `json:"history_commits,omitempty"`
	HistoryObjects int             `json:"history_objects,omitempty"`
	StashCommit    string          `json:"stash_commit,omitempty"`
	StashFiles     int             `json:"stash_files,omitempty"`
	Files          []FileRecord    `json:"files,omitempty"`
	Missing        []string        `json:"missing"`
	Warnings       []string        `json:"warnings"`
	Extras         []string        `json:"extras"`
	Secrets        []SecretFinding `json:"secrets"`
	Error          string          `json:"error"`
	ElapsedMS      int64           `json:"elapsed_ms"`
}

// Report is the top level JSON document.
type Report struct {
	Tool        string          `json:"tool"`
	Version     string          `json:"version"`
	GeneratedAt string          `json:"generated_at"`
	Targets     []*TargetResult `json:"targets"`
}

// NewReport builds an empty report.
func NewReport() *Report {
	return &Report{Tool: "gitleak", Version: Version, GeneratedAt: time.Now().Format(time.RFC3339)}
}

// WriteReport serialises the report to path (creating parent directories).
func WriteReport(path string, r *Report) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func newTargetResult(det *Detection) *TargetResult {
	res := &TargetResult{
		Input:      det.Target.Input,
		Root:       det.Target.Root,
		Vulnerable: det.Vulnerable,
		Score:      det.Score,
		Soft404:    det.Soft404,
		HeadRef:    det.HeadRef,
		HeadCommit: det.HeadObject,
		Evidence:   append([]string{}, det.Evidence...),
		Extras:     append([]string{}, det.Extras...),
		Missing:    []string{},
		Warnings:   append([]string{}, det.Errors...),
		Secrets:    []SecretFinding{},
		ElapsedMS:  det.Elapsed.Milliseconds(),
	}
	if len(det.RemoteURLs) > 0 {
		res.Remote = det.RemoteURLs[0]
	}
	res.RemoteCreds = det.RemoteCreds
	if det.NetworkErr && len(det.Errors) > 0 && res.Error == "" {
		res.Error = det.Errors[0]
	}
	return res
}

// idsToHex renders object ids for reporting.
func idsToHex(ids []gitx.ObjectID) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[gitx.ObjectID]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id.IsZero() || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id.String())
	}
	sort.Strings(out)
	return out
}

// SummaryLine renders a compact one line description for scan output.
func (r *TargetResult) SummaryLine() string {
	if !r.Vulnerable {
		if r.Error != "" {
			return fmt.Sprintf("%s  (error: %s)", r.Root, r.Error)
		}
		return fmt.Sprintf("%s  (not vulnerable)", r.Root)
	}
	parts := []string{r.Root}
	if r.HeadRef != "" {
		parts = append(parts, "ref="+headRefName(r.HeadRef))
	}
	if r.HeadCommit != "" {
		parts = append(parts, "commit="+r.HeadCommit[:8])
	}
	if r.Remote != "" {
		parts = append(parts, "remote="+r.Remote)
	}
	if r.FilesRestored > 0 {
		parts = append(parts, fmt.Sprintf("files=%d", r.FilesRestored))
	}
	return fmt.Sprintf("%s", joinParts(parts))
}

func joinParts(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "  "
		}
		out += p
	}
	return out
}
