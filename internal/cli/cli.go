// Package cli implements the gitleak command line interface.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gitleak/internal/app"
	"gitleak/internal/httpc"
	"gitleak/internal/i18n"
	"gitleak/internal/ui"
)

// headerFlags collects repeated -H K:V arguments.
type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ", ") }

// Set implements flag.Value.
func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// options holds every command line flag shared by the subcommands.
type options struct {
	list        string
	out         string
	jsonPath    string
	concurrency int
	perHost     int
	rate        float64
	timeout     time.Duration
	retries     int
	userAgent   string
	headers     headerFlags
	proxy       string
	insecure    bool
	maxBodyMB   int
	threads     int
	history     bool
	allBranches bool
	writeGit    bool
	resume      bool
	scanSecrets bool
	extra       bool
	noExtract   bool
	maxPackMB   int
	maxObjects  int
	lang        string
	debug       bool
	quiet       bool
	noColor     bool
}

func defaultOptions() *options {
	return &options{
		out:         "gitleak-out",
		concurrency: 64,
		perHost:     8,
		timeout:     10 * time.Second,
		retries:     3,
		userAgent:   "gitleak/" + app.Version,
		maxBodyMB:   64,
		threads:     32,
		maxPackMB:   1024,
		maxObjects:  200000,
	}
}

func (o *options) validate() error {
	if o.concurrency < 1 {
		o.concurrency = 1
	}
	if o.perHost < 1 {
		o.perHost = 1
	}
	if o.threads < 1 {
		o.threads = 1
	}
	if o.retries < 0 {
		o.retries = 0
	}
	if o.timeout <= 0 {
		return errors.New(i18n.Tr("--timeout must be positive"))
	}
	if o.maxBodyMB <= 0 {
		return errors.New(i18n.Tr("--max-body must be positive"))
	}
	if o.maxPackMB <= 0 {
		o.maxPackMB = 1024
	}
	if o.maxObjects < 0 {
		o.maxObjects = 0
	}
	if o.out == "" {
		return errors.New(i18n.Tr("--out must not be empty"))
	}
	return nil
}

func registerFlags(fs *flag.FlagSet, o *options) {
	fs.StringVar(&o.list, "l", o.list, "read targets from a file (- for stdin)")
	fs.StringVar(&o.list, "list", o.list, "read targets from a file (- for stdin)")
	fs.StringVar(&o.out, "o", o.out, "output directory")
	fs.StringVar(&o.out, "out", o.out, "output directory")
	fs.StringVar(&o.jsonPath, "json", o.jsonPath, "write the JSON report to this file")
	fs.IntVar(&o.concurrency, "c", o.concurrency, "global concurrent requests")
	fs.IntVar(&o.concurrency, "concurrency", o.concurrency, "global concurrent requests")
	fs.IntVar(&o.perHost, "per-host", o.perHost, "concurrent requests per host")
	fs.Float64Var(&o.rate, "rate", o.rate, "requests per second (0 = unlimited)")
	fs.DurationVar(&o.timeout, "t", o.timeout, "per request timeout")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "per request timeout")
	fs.IntVar(&o.retries, "retries", o.retries, "retries per request")
	fs.StringVar(&o.userAgent, "A", o.userAgent, "User-Agent header")
	fs.StringVar(&o.userAgent, "user-agent", o.userAgent, "User-Agent header")
	fs.Var(&o.headers, "H", "extra request header (K:V, repeatable)")
	fs.Var(&o.headers, "header", "extra request header (K:V, repeatable)")
	fs.StringVar(&o.proxy, "proxy", o.proxy, "HTTP or SOCKS5 proxy URL")
	fs.BoolVar(&o.insecure, "k", o.insecure, "skip TLS certificate verification")
	fs.BoolVar(&o.insecure, "insecure", o.insecure, "skip TLS certificate verification")
	fs.IntVar(&o.maxBodyMB, "max-body", o.maxBodyMB, "maximum response body size in MB")
	fs.IntVar(&o.threads, "threads", o.threads, "worker goroutines")
	fs.BoolVar(&o.history, "history", o.history, "download the full commit history")
	fs.BoolVar(&o.allBranches, "all-branches", o.allBranches, "follow every ref while downloading history")
	fs.BoolVar(&o.writeGit, "write-git", o.writeGit, "materialise a usable .git directory (implies --history)")
	fs.BoolVar(&o.resume, "resume", o.resume, "reuse previously cached objects")
	fs.BoolVar(&o.scanSecrets, "scan-secrets", o.scanSecrets, "scan restored files for credentials")
	fs.BoolVar(&o.extra, "extra", o.extra, "probe extra leak paths")
	fs.BoolVar(&o.noExtract, "no-extract", o.noExtract, "detect only, download nothing")
	fs.IntVar(&o.maxPackMB, "max-pack", o.maxPackMB, "maximum packfile size in MB")
	fs.IntVar(&o.maxObjects, "max-objects", o.maxObjects, "maximum history objects")
	fs.BoolVar(&o.debug, "debug", o.debug, "verbose debug output")
	fs.BoolVar(&o.quiet, "quiet", o.quiet, "suppress banners and progress")
	fs.StringVar(&o.lang, "lang", o.lang, "output language: en or zh")
	fs.BoolVar(&o.noColor, "no-color", o.noColor, "disable ANSI colours")
}

// Run executes the CLI and returns the process exit code.
func Run(args []string) int {
	lang, err := resolveLang(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitleak: %v\n", err)
		return 1
	}
	i18n.Set(lang)
	usageText = usageFor(lang)
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, usageText)
		return 1
	}
	cmd := args[0]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usageText)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintf(os.Stdout, "gitleak %s\n", app.Version)
		return 0
	case "scan":
		return runScanOrAuto(args[1:], false)
	case "auto":
		return runScanOrAuto(args[1:], true)
	case "dump":
		return runDump(args[1:])
	default:
		if topLevelAuto(args) {
			return runAutoMode(stripAuto(args))
		}
		fmt.Fprintf(os.Stderr, i18n.Format("gitleak: unknown subcommand %q\n\n%s", cmd, usageText))
		return 1
	}
}

// boolFlags lists the flags that never consume a following argument. It lets
// reorderArgs accept flags placed after positional arguments (Go's flag package
// stops parsing at the first non-flag token).
var boolFlags = map[string]bool{
	"k": true, "insecure": true,
	"history": true, "all-branches": true, "write-git": true, "resume": true,
	"scan-secrets": true, "extra": true, "no-extract": true,
	"debug": true, "quiet": true, "no-color": true,
	"h": true, "help": true,
}

// reorderArgs moves every flag (and its value) before the positional arguments,
// so both "scan URL -o out" and "scan -o out URL" work.
func reorderArgs(args []string) []string {
	flags := make([]string, 0, len(args))
	positional := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 1 && (a[0] == '-' || a[0] == '/') {
			flags = append(flags, a)
			if strings.Contains(a, "=") {
				continue
			}
			name := strings.TrimLeft(a, "-/")
			if boolFlags[name] {
				continue
			}
			if i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func parseOptions(name string, args []string) (*options, []string, int) {
	o := defaultOptions()
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerFlags(fs, o)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stdout, usageText)
			return nil, nil, 0
		}
		fmt.Fprintf(os.Stderr, i18n.Format("gitleak: %v\n\n%s", err, usageText))
		return nil, nil, 1
	}
	if o.lang != "" {
		l, ok := i18n.Parse(o.lang)
		if !ok {
			fmt.Fprintf(os.Stderr, "gitleak: unsupported language %q (supported: en, zh)\n", o.lang)
			return nil, nil, 1
		}
		i18n.Set(l)
		usageText = usageFor(l)
	}
	if err := o.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "gitleak: %v\n", err)
		return nil, nil, 1
	}
	return o, fs.Args(), -1
}

func newUI(o *options) *ui.UI {
	color := !o.noColor && ui.IsTTY(os.Stdout)
	return ui.New(os.Stdout, os.Stderr, color, o.quiet, o.debug)
}

func newClient(o *options, u *ui.UI) (*httpc.Client, error) {
	headers := http.Header{}
	for _, raw := range o.headers {
		name, value, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf(i18n.Tr("invalid header %q (want K:V)"), raw)
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	opts := httpc.Options{
		Timeout:       o.timeout,
		Retries:       o.retries,
		Concurrency:   o.concurrency,
		PerHost:       o.perHost,
		RatePerSecond: o.rate,
		UserAgent:     o.userAgent,
		Headers:       headers,
		Proxy:         o.proxy,
		Insecure:      o.insecure,
		MaxBody:       int64(o.maxBodyMB) << 20,
		Stats:         &httpc.Stats{},
	}
	if o.debug {
		opts.Debug = func(format string, args ...any) { u.Debugf(format, args...) }
	}
	return httpc.New(opts)
}

func collectTargets(args []string, listPath string) []app.Target {
	raw := append([]string{}, args...)
	if listPath != "" {
		var data []byte
		var err error
		if listPath == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(listPath)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, i18n.Format("gitleak: cannot read target list: %v\n", err))
			return nil
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		sc.Buffer(make([]byte, 64*1024), 4<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			raw = append(raw, line)
		}
	}
	out := make([]app.Target, 0, len(raw))
	for _, r := range raw {
		t, err := app.ParseTarget(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, i18n.Format("gitleak: skipping %q: %v\n", r, err))
			continue
		}
		out = append(out, t)
	}
	return out
}

func formatBytes(n int64) string {
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

func printStats(u *ui.UI, c *httpc.Client) {
	st := c.Stats().Snapshot()
	u.Rawf("requests=%d retries=%d errors=%d bytes=%s 2xx=%d 4xx=%d 5xx=%d",
		st.Requests, st.Retries, st.Errors, formatBytes(int64(st.Bytes)),
		st.Status2xx, st.Status4xx, st.Status5xx)
}

func writeReport(o *options, report *app.Report) bool {
	if o.jsonPath == "" {
		return true
	}
	if err := app.WriteReport(o.jsonPath, report); err != nil {
		fmt.Fprintf(os.Stderr, i18n.Format("gitleak: cannot write report: %v\n", err))
		return false
	}
	return true
}

func dumpOptions(o *options) app.DumpOptions {
	return app.DumpOptions{
		OutRoot:     o.out,
		History:     o.history,
		AllBranches: o.allBranches,
		WriteGit:    o.writeGit,
		Resume:      o.resume,
		Extract:     !o.noExtract,
		ScanSecrets: o.scanSecrets,
		Extra:       o.extra,
		MaxPackMB:   o.maxPackMB,
		MaxObjects:  o.maxObjects,
		Workers:     o.threads,
	}
}

func runScanOrAuto(args []string, auto bool) int {
	name := "scan"
	if auto {
		name = "auto"
	}
	o, positional, code := parseOptions(name, args)
	if code >= 0 {
		return code
	}
	targets := collectTargets(positional, o.list)
	if len(targets) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 1
	}
	u := newUI(o)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := newClient(o, u)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitleak: %v\n", err)
		return 3
	}
	defer c.Close()
	u.Banner(app.Version)
	bc := app.NewBaselineCache()
	results := app.Scan(ctx, c, targets, bc, u, app.ScanOptions{
		Workers: o.threads,
		Extra:   o.extra,
		OutRoot: o.out,
	})
	if auto {
		for i := range results {
			if results[i] == nil || !results[i].Vulnerable {
				continue
			}
			det := app.Detect(ctx, c, targets[i], bc, true)
			if !det.Vulnerable && det.NetworkErr && !targets[i].ExplicitScheme {
				alt := targets[i].WithScheme("http")
				if det2 := app.Detect(ctx, c, alt, bc, true); det2.Vulnerable {
					det = det2
				}
			}
			results[i] = app.Dump(ctx, c, det, dumpOptions(o), u)
		}
	}
	clean := make([]*app.TargetResult, 0, len(results))
	for _, r := range results {
		if r != nil {
			clean = append(clean, r)
		}
	}
	report := app.NewReport()
	report.Targets = clean
	if !o.quiet {
		for _, r := range clean {
			if r.Vulnerable {
				u.Goodf("%s", r.SummaryLine())
			} else {
				u.Infof("%s", r.SummaryLine())
			}
		}
		u.Rawf("")
		printStats(u, c)
	}
	if !writeReport(o, report) {
		return 3
	}
	found := 0
	restored := 0
	var restoredBytes int64
	for _, r := range clean {
		if r.Vulnerable {
			found++
		}
		if r.FilesRestored > 0 {
			restored++
			restoredBytes += r.Bytes
		}
	}
	if !o.quiet {
		u.Rawf("targets=%d vulnerable=%d restored=%d files=%s", len(clean), found, restoredBytes, "")
	}
	if restored > 0 {
		return 0
	}
	if found > 0 {
		if auto {
			return 3
		}
		return 0
	}
	return 2
}

func runDump(args []string) int {
	o, positional, code := parseOptions("dump", args)
	if code >= 0 {
		return code
	}
	targets := collectTargets(positional, o.list)
	if len(targets) != 1 {
		fmt.Fprintf(os.Stderr, i18n.Format("gitleak: dump expects exactly one target, got %d\n\n%s", len(targets), usageText))
		return 1
	}
	u := newUI(o)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := newClient(o, u)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitleak: %v\n", err)
		return 3
	}
	defer c.Close()
	u.Banner(app.Version)
	bc := app.NewBaselineCache()
	t := targets[0]
	det := app.Detect(ctx, c, t, bc, true)
	if !det.Vulnerable && det.NetworkErr && !t.ExplicitScheme {
		alt := t.WithScheme("http")
		if det2 := app.Detect(ctx, c, alt, bc, true); det2.Vulnerable {
			det = det2
		}
	}
	res := app.Dump(ctx, c, det, dumpOptions(o), u)
	report := app.NewReport()
	report.Targets = []*app.TargetResult{res}
	if !o.quiet {
		u.Rawf("")
		u.Goodf("%s", res.SummaryLine())
		printStats(u, c)
	}
	if !writeReport(o, report) {
		return 3
	}
	if !res.Vulnerable {
		return 2
	}
	if res.FilesRestored > 0 {
		return 0
	}
	return 3
}

// autoReportSuffix is appended to the target slug for the JSON report that top
// level auto mode writes when --json is not given.
const autoReportSuffix = ".json"

// topLevelAuto reports whether the command line asks for the one-shot --auto
// mode. It is only consulted when the first argument is not a known subcommand,
// so "gitleak --auto URL", "gitleak -o out --auto URL" and "gitleak URL --auto"
// all reach it, while "gitleak dump --auto URL" stays a normal dump invocation.
func topLevelAuto(args []string) bool {
	for _, a := range args {
		if a == "--auto" || a == "-auto" {
			return true
		}
	}
	return false
}

// stripAuto removes the --auto switch before the regular flag parser runs.
func stripAuto(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--auto" || a == "-auto" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// runAutoMode implements "gitleak --auto <url>": detect the target and, if it is
// exposed, perform the full repository dump (history, every branch and a usable
// .git directory) without requiring the caller to repeat those flags. A JSON
// report is written automatically next to the dump unless --json overrides it.
func runAutoMode(args []string) int {
	o, positional, code := parseOptions("auto", args)
	if code >= 0 {
		return code
	}
	if o.noExtract {
		fmt.Fprintln(os.Stderr, i18n.Tr("gitleak: --no-extract cannot be combined with --auto"))
		return 1
	}
	targets := collectTargets(positional, o.list)
	if len(targets) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 1
	}
	// Auto mode is always the full dump.
	o.history = true
	o.allBranches = true
	o.writeGit = true

	u := newUI(o)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := newClient(o, u)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitleak: %v\n", err)
		return 3
	}
	defer c.Close()
	u.Banner(app.Version)
	u.Infof("auto mode: detect + full dump (--history --all-branches --write-git)")
	bc := app.NewBaselineCache()
	results := make([]*app.TargetResult, 0, len(targets))
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		det := app.Detect(ctx, c, t, bc, true)
		if !det.Vulnerable && det.NetworkErr && !t.ExplicitScheme {
			alt := t.WithScheme("http")
			if det2 := app.Detect(ctx, c, alt, bc, true); det2.Vulnerable {
				det = det2
			}
		}
		res := app.Dump(ctx, c, det, dumpOptions(o), u)
		results = append(results, res)
		// Leave a machine readable report next to the dump unless the caller
		// asked for a specific --json path.
		if o.jsonPath == "" && res.Vulnerable && res.OutDir != "" {
			path := filepath.Join(o.out, t.Slug()+autoReportSuffix)
			rep := app.NewReport()
			rep.Targets = []*app.TargetResult{res}
			if werr := app.WriteReport(path, rep); werr != nil {
				fmt.Fprintf(os.Stderr, i18n.Format("gitleak: cannot write report: %v\n", werr))
			} else if !o.quiet {
				u.Infof("  report: %s", path)
			}
		}
	}
	report := app.NewReport()
	report.Targets = results
	if !o.quiet {
		u.Rawf("")
		for _, r := range results {
			if r.Vulnerable {
				u.Goodf("%s", r.SummaryLine())
			} else {
				u.Infof("%s", r.SummaryLine())
			}
		}
		u.Rawf("")
		printStats(u, c)
	}
	if !writeReport(o, report) {
		return 3
	}
	found, restored := 0, 0
	for _, r := range results {
		if r.Vulnerable {
			found++
		}
		if r.FilesRestored > 0 {
			restored++
		}
	}
	if restored > 0 {
		return 0
	}
	if found > 0 {
		return 3
	}
	return 2
}

// langFlagValue finds an explicit --lang value on the raw command line, before
// the flag package runs, so help and usage errors already use the right language.
func langFlagValue(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		for _, name := range []string{"--lang", "-lang"} {
			if a == name {
				if i+1 < len(args) {
					return args[i+1], true
				}
				return "", true
			}
			if strings.HasPrefix(a, name+"=") {
				return a[len(name)+1:], true
			}
		}
	}
	return "", false
}

// resolveLang combines --lang, GITLEAK_LANG and the build default.
func resolveLang(args []string) (i18n.Lang, error) {
	if raw, ok := langFlagValue(args); ok {
		l, good := i18n.Parse(raw)
		if !good {
			return i18n.EN, fmt.Errorf("unsupported language %q (supported: en, zh)", raw)
		}
		return l, nil
	}
	return i18n.Detect(), nil
}
