package app

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// Target is a normalised web target that may expose a .git directory.
type Target struct {
	Input          string
	Scheme         string
	Host           string
	Path           string
	Root           string
	Git            string
	ExplicitScheme bool
}

// ParseTarget normalises a user supplied target such as
// "example.com/app", "https://example.com/app/.git/" or
// "https://example.com/.git/HEAD".
func ParseTarget(raw string) (Target, error) {
	t := Target{Input: strings.TrimSpace(raw)}
	s := t.Input
	if s == "" {
		return t, fmt.Errorf("empty target")
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	lower := strings.ToLower(s)
	explicit := false
	for _, prefix := range []string{"http://", "https://"} {
		if strings.HasPrefix(lower, prefix) {
			explicit = true
			break
		}
	}
	if !explicit {
		if strings.Contains(s, "://") {
			return t, fmt.Errorf("unsupported scheme in %q (only http and https are supported)", raw)
		}
		if strings.HasPrefix(s, "//") {
			s = "https:" + s
		} else {
			s = "https://" + s
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return t, fmt.Errorf("invalid target %q: %w", raw, err)
	}
	if u.Host == "" {
		return t, fmt.Errorf("invalid target %q: missing host", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return t, fmt.Errorf("invalid target %q: unsupported scheme %q", raw, u.Scheme)
	}
	p := u.EscapedPath()
	p = strings.TrimRight(p, "/")
	lp := strings.ToLower(p)
	for _, suffix := range []string{"/.git/head", "/.git/head/"} {
		if strings.HasSuffix(lp, suffix) {
			p = p[:len(p)-len(suffix)]
			lp = strings.ToLower(p)
			break
		}
	}
	if strings.HasSuffix(lp, "/.git") {
		p = p[:len(p)-len("/.git")]
		lp = strings.ToLower(p)
	}
	if strings.HasSuffix(lp, "/.git") {
		p = p[:len(p)-len("/.git")]
	}
	if p == "/" {
		p = ""
	}
	t.Scheme = u.Scheme
	t.ExplicitScheme = explicit
	t.Host = u.Host
	t.Path = p
	t.Root = u.Scheme + "://" + u.Host + p
	t.Git = t.Root + "/.git"
	return t, nil
}

// WithScheme returns a copy of the target with another scheme.
func (t Target) WithScheme(scheme string) Target {
	nt := t
	nt.Scheme = scheme
	nt.Root = scheme + "://" + t.Host + t.Path
	nt.Git = nt.Root + "/.git"
	return nt
}

// Probe builds a URL below the .git directory.
func (t Target) Probe(name string) string { return t.Git + "/" + name }

// Slug returns a deterministic, filesystem safe output directory name.
func (t Target) Slug() string {
	sum := sha1.Sum([]byte(t.Root))
	base := t.Host + t.Path
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 48 {
		s = s[:48]
	}
	if s == "" {
		s = "target"
	}
	return s + "_" + hex.EncodeToString(sum[:])[:8]
}

// parseHead splits a HEAD file body into ref and object id.
func parseHead(body string) (ref, oid string) {
	body = strings.TrimSpace(body)
	if rest, ok := strings.CutPrefix(body, "ref: "); ok {
		return strings.TrimSpace(rest), ""
	}
	if len(body) >= 40 {
		return "", strings.ToLower(body[:40])
	}
	return "", ""
}
