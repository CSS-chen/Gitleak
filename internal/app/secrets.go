package app

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gitleak/internal/i18n"
	"gitleak/internal/ui"
)

type secretPattern struct {
	kind string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"AWS access key id", regexp.MustCompile("AKIA[0-9A-Z]{16}")},
	{"Private key block", regexp.MustCompile("-----BEGIN ([A-Z]+ )?PRIVATE KEY-----")},
	{"GitHub token", regexp.MustCompile("gh[pousr]_[A-Za-z0-9]{36,}")},
	{"Slack token", regexp.MustCompile("xox[baprs]-[A-Za-z0-9-]{10,}")},
	{"Google API key", regexp.MustCompile("AIza[0-9A-Za-z_-]{35}")},
	{"Stripe secret key", regexp.MustCompile("sk_live_[0-9A-Za-z]{16,}")},
	{"JSON web token", regexp.MustCompile("eyJ[A-Za-z0-9_-]{10,}[.]eyJ[A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}")},
	{"Hardcoded credential", regexp.MustCompile("(?i)(password|passwd|pwd|secret|api[_-]?key|token)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{6,}[\"']")},
}

var binaryExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true,
	".pdf": true, ".zip": true, ".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".7z": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wav": true, ".ogg": true,
	".class": true, ".jar": true, ".so": true, ".dll": true, ".exe": true, ".o": true, ".a": true,
	".pyc": true, ".wasm": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
}

// scanSecrets inspects restored text files for common credential patterns.
func scanSecrets(root string, records []FileRecord, u *ui.UI) []SecretFinding {
	var out []SecretFinding
	for _, rec := range records {
		if rec.Mode == "120000" || rec.Mode == "160000" {
			continue
		}
		if binaryExt[strings.ToLower(filepath.Ext(rec.Path))] {
			continue
		}
		if rec.Bytes > 2<<20 {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(rec.Path))
		data, err := os.ReadFile(full)
		if err != nil || len(data) == 0 {
			continue
		}
		if strings.IndexByte(string(data[:min(len(data), 8192)]), 0) >= 0 {
			continue
		}
		text := string(data)
		for _, p := range secretPatterns {
			match := p.re.FindString(text)
			if match == "" {
				continue
			}
			if len(match) > 160 {
				match = match[:160]
			}
			out = append(out, SecretFinding{Path: rec.Path, Kind: p.kind, Match: match})
			if u != nil {
				u.Warnf("possible secret in %s: %s", rec.Path, i18n.Tr(p.kind))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
