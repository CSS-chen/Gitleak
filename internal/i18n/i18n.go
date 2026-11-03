// Package i18n provides the tiny English/Chinese message catalogue used by the
// gitleak command line interface.
package i18n

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

// Lang identifies an output language.
type Lang string

// Supported languages.
const (
	EN Lang = "en"
	ZH Lang = "zh"
)

// BuildDefault is the language compiled into the binary. Release builds set it
// with: go build -ldflags "-X gitleak/internal/i18n.BuildDefault=zh".
var BuildDefault = "en"

var current atomic.Value

func init() {
	current.Store(EN)
}

// Parse maps a user supplied language tag to a supported Lang.
func Parse(s string) (Lang, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "en", "en-us", "en-gb", "english":
		return EN, true
	case "zh", "zh-cn", "zh-hans", "zh-hant", "chinese", "中文":
		return ZH, true
	}
	return "", false
}

// Detect resolves the language from GITLEAK_LANG, then the build default.
func Detect() Lang {
	if l, ok := Parse(os.Getenv("GITLEAK_LANG")); ok {
		return l
	}
	if l, ok := Parse(BuildDefault); ok {
		return l
	}
	return EN
}

// Set changes the active language. Call it before worker goroutines start.
func Set(l Lang) {
	if l != ZH {
		l = EN
	}
	current.Store(l)
}

// Current reports the active language.
func Current() Lang { return current.Load().(Lang) }

// IsZH reports whether Chinese is active.
func IsZH() bool { return Current() == ZH }

// Tr translates a plain English message. Unknown messages are returned
// unchanged, so every string keeps an English fallback.
func Tr(s string) string {
	if Current() != ZH {
		return s
	}
	if t, ok := zh[s]; ok {
		return t
	}
	return s
}

// Format translates an English format string, then formats it with args.
func Format(format string, args ...any) string {
	return fmt.Sprintf(Tr(format), args...)
}
