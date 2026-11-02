// Package ui provides small, dependency free terminal output helpers with
// optional colour and a live progress line.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// ANSI colour codes.
const (
	Reset  = "[0m"
	Bold   = "[1m"
	Dim    = "[2m"
	Red    = "[31m"
	Green  = "[32m"
	Yellow = "[33m"
	Blue   = "[34m"
	Cyan   = "[36m"
)

// UI is a concurrency safe writer for human readable output.
type UI struct {
	mu     sync.Mutex
	out    io.Writer
	errOut io.Writer
	color  bool
	quiet  bool
	debug  bool
}

// New builds a UI. Color should only be enabled for terminals.
func New(out, errOut io.Writer, color, quiet, debug bool) *UI {
	return &UI{out: out, errOut: errOut, color: color, quiet: quiet, debug: debug}
}

// IsTTY reports whether f is an interactive terminal.
func IsTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled reports whether ANSI colour is active.
func (u *UI) ColorEnabled() bool { return u.color }

func (u *UI) paint(code, s string) string {
	if !u.color {
		return s
	}
	return code + s + Reset
}

func (u *UI) printf(w io.Writer, format string, args ...any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(w, format+"\n", args...)
}

// Infof prints a neutral line.
func (u *UI) Infof(format string, args ...any) {
	if u.quiet {
		return
	}
	u.printf(u.out, format, args...)
}

// Goodf prints a success line.
func (u *UI) Goodf(format string, args ...any) {
	if u.quiet {
		return
	}
	u.printf(u.out, u.paint(Green, "  + ")+format, args...)
}

// Warnf prints a warning line.
func (u *UI) Warnf(format string, args ...any) {
	u.printf(u.errOut, u.paint(Yellow, "  ! ")+format, args...)
}

// Errorf prints an error line.
func (u *UI) Errorf(format string, args ...any) {
	u.printf(u.errOut, u.paint(Red, "  x ")+format, args...)
}

// Debugf prints only when debug mode is on.
func (u *UI) Debugf(format string, args ...any) {
	if !u.debug {
		return
	}
	u.printf(u.errOut, u.paint(Dim, "  . ")+format, args...)
}

// Rawf prints without decoration.
func (u *UI) Rawf(format string, args ...any) {
	if u.quiet {
		return
	}
	u.printf(u.out, format, args...)
}

// Outf prints to stdout regardless of quiet.
func (u *UI) Outf(format string, args ...any) {
	u.printf(u.out, format, args...)
}

// Banner prints the tool banner.
func (u *UI) Banner(version string) {
	if u.quiet {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	line := strings.Repeat("-", 62)
	fmt.Fprintln(u.out, u.paint(Cyan, line))
	fmt.Fprintln(u.out, u.paint(Bold+Cyan, "  gitleak ")+u.paint(Dim, version)+
		"  fast .git leak scanner & repository dumper")
	fmt.Fprintln(u.out, u.paint(Dim, "  use only against systems you are authorised to test"))
	fmt.Fprintln(u.out, u.paint(Cyan, line))
}

// Progress rewrites the current line on stderr.
func (u *UI) Progress(format string, args ...any) {
	if u.quiet {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.errOut, "\r\x1b[2K  ~ "+format, args...)
}

// ClearProgress erases the progress line.
func (u *UI) ClearProgress() {
	if u.quiet {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprint(u.errOut, "\r\x1b[2K")
}

// Plain returns s without ANSI escapes if colour is disabled.
func (u *UI) Plain(s string) string {
	if u.color {
		return s
	}
	for _, code := range []string{Reset, Bold, Dim, Red, Green, Yellow, Blue, Cyan} {
		s = strings.ReplaceAll(s, code, "")
	}
	return s
}
