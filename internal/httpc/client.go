// Package httpc provides the concurrent, rate limited HTTP engine used by
// gitleak. It is built on net/http with no third party dependencies and
// supports retries, per-host limits, global concurrency caps, HTTP/SOCKS5
// proxies and bounded response bodies.
package httpc

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrBodyTooLarge is returned when a response exceeds the body limit.
	ErrBodyTooLarge = errors.New("httpc: response body exceeds limit")
	// ErrRetriesExhausted wraps the last transport error after all retries.
	ErrRetriesExhausted = errors.New("httpc: retries exhausted")
)

// Stats aggregates live counters, safe for concurrent use.
type Stats struct {
	Requests  atomic.Uint64
	Retries   atomic.Uint64
	Errors    atomic.Uint64
	Bytes     atomic.Uint64
	Status2xx atomic.Uint64
	Status3xx atomic.Uint64
	Status4xx atomic.Uint64
	Status5xx atomic.Uint64
	InFlight  atomic.Int64
	TotalWait atomic.Uint64 // nanoseconds spent in rate limiter
}

// Snapshot is a plain copy of the counters for display/logging.
type Snapshot struct {
	Requests  uint64
	Retries   uint64
	Errors    uint64
	Bytes     uint64
	Status2xx uint64
	Status3xx uint64
	Status4xx uint64
	Status5xx uint64
	InFlight  int64
}

// Snapshot returns the current counter values.
func (s *Stats) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	return Snapshot{
		Requests:  s.Requests.Load(),
		Retries:   s.Retries.Load(),
		Errors:    s.Errors.Load(),
		Bytes:     s.Bytes.Load(),
		Status2xx: s.Status2xx.Load(),
		Status3xx: s.Status3xx.Load(),
		Status4xx: s.Status4xx.Load(),
		Status5xx: s.Status5xx.Load(),
		InFlight:  s.InFlight.Load(),
	}
}

// Options configures a Client.
type Options struct {
	Timeout       time.Duration
	Retries       int
	Concurrency   int
	PerHost       int
	RatePerSecond float64
	UserAgent     string
	Headers       http.Header
	Proxy         string
	Insecure      bool
	MaxBody       int64
	Debug         func(format string, args ...any)
	Stats         *Stats
}

// Response is a fully buffered HTTP response.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	URL        string
	Elapsed    time.Duration
	Retries    int
}

// OK reports a 2xx status.
func (r *Response) OK() bool { return r.StatusCode >= 200 && r.StatusCode < 300 }

// NotFound reports 404/410.
func (r *Response) NotFound() bool {
	return r.StatusCode == http.StatusNotFound || r.StatusCode == http.StatusGone
}

// Text returns the body as a string (used for validation).
func (r *Response) Text() string { return string(r.Body) }

// Client is a concurrency limited HTTP client.
type Client struct {
	hc        *http.Client
	opts      Options
	sem       chan struct{}
	hostMu    sync.Mutex
	hostSem   map[string]chan struct{}
	limiter   *rateLimiter
	transport *http.Transport
}

// New builds a Client.
func New(opts Options) (*Client, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 64
	}
	if opts.PerHost <= 0 {
		opts.PerHost = 8
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 64 << 20
	}
	if opts.Headers == nil {
		opts.Headers = make(http.Header)
	}
	if opts.UserAgent != "" {
		opts.Headers.Set("User-Agent", opts.UserAgent)
	}
	if opts.Stats == nil {
		opts.Stats = &Stats{}
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          opts.Concurrency * 2,
		MaxIdleConnsPerHost:   opts.PerHost * 2,
		MaxConnsPerHost:       opts.PerHost + 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.Insecure}, //nolint:gosec // explicit opt-in for pentest targets
	}
	if opts.Proxy != "" {
		pu, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy %q: %w", opts.Proxy, err)
		}
		switch strings.ToLower(pu.Scheme) {
		case "http", "https":
			tr.Proxy = http.ProxyURL(pu)
		case "socks5", "socks5h":
			dialer := &net.Dialer{Timeout: opts.Timeout, KeepAlive: 30 * time.Second}
			tr.DialContext = socks5DialContext(pu, dialer)
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, socks5 or socks5h)", pu.Scheme)
		}
	}
	c := &Client{opts: opts, transport: tr, hostSem: make(map[string]chan struct{})}
	c.sem = make(chan struct{}, opts.Concurrency)
	if opts.RatePerSecond > 0 {
		c.limiter = newRateLimiter(opts.RatePerSecond)
	}
	c.hc = &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
	return c, nil
}

// Close releases idle connections.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
}

// Stats returns the shared statistics.
func (c *Client) Stats() *Stats { return c.opts.Stats }

// Options returns a copy of the configuration.
func (c *Client) Options() Options { return c.opts }

func (c *Client) debugf(format string, args ...any) {
	if c.opts.Debug != nil {
		c.opts.Debug(format, args...)
	}
}

func (c *Client) hostChannel(host string) chan struct{} {
	c.hostMu.Lock()
	defer c.hostMu.Unlock()
	ch, ok := c.hostSem[host]
	if !ok {
		ch = make(chan struct{}, c.opts.PerHost)
		c.hostSem[host] = ch
	}
	return ch
}

// Get fetches rawURL, retrying transient failures, and returns a buffered
// response. A non-2xx status is not an error: callers inspect StatusCode.
func (c *Client) Get(ctx context.Context, rawURL string, maxBody int64) (*Response, error) {
	if maxBody <= 0 {
		maxBody = c.opts.MaxBody
	}
	attempts := c.opts.Retries + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			c.opts.Stats.Retries.Add(1)
			delay := backoff(attempt)
			c.debugf("retry %d/%d for %s in %s", attempt, attempts-1, rawURL, delay)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		resp, err := c.doOnce(ctx, rawURL, maxBody)
		if err != nil {
			lastErr = err
			if !retryableError(err) || ctx.Err() != nil || attempt == attempts-1 {
				break
			}
			continue
		}
		if retryableStatus(resp.StatusCode) && attempt < attempts-1 {
			lastErr = fmt.Errorf("httpc: server returned %d", resp.StatusCode)
			if ra := retryAfter(resp.Header); ra > 0 {
				c.debugf("server asked to wait %s before retry", ra)
				select {
				case <-ctx.Done():
					return resp, ctx.Err()
				case <-time.After(ra):
				}
			}
			continue
		}
		resp.Retries = attempt
		return resp, nil
	}
	c.opts.Stats.Errors.Add(1)
	if lastErr == nil {
		lastErr = errors.New("httpc: request failed")
	}
	return nil, fmt.Errorf("%w: %v", ErrRetriesExhausted, lastErr)
}

func (c *Client) doOnce(ctx context.Context, rawURL string, maxBody int64) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("httpc: invalid url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("httpc: unsupported scheme %q", u.Scheme)
	}
	host := strings.ToLower(u.Host)
	hostCh := c.hostChannel(host)
	select {
	case hostCh <- struct{}{}:
		defer func() { <-hostCh }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c.limiter != nil {
		start := time.Now()
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		c.opts.Stats.TotalWait.Add(uint64(time.Since(start)))
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("httpc: build request: %w", err)
	}
	for k, vals := range c.opts.Headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "*/*")
	start := time.Now()
	c.opts.Stats.Requests.Add(1)
	c.opts.Stats.InFlight.Add(1)
	resp, err := c.hc.Do(req)
	c.opts.Stats.InFlight.Add(-1)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("httpc: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("httpc: read body: %w", err)
	}
	if int64(len(body)) > maxBody {
		return nil, fmt.Errorf("%w: %s > %d bytes", ErrBodyTooLarge, u.Redacted(), maxBody)
	}
	c.opts.Stats.Bytes.Add(uint64(len(body)))
	switch {
	case resp.StatusCode >= 500:
		c.opts.Stats.Status5xx.Add(1)
	case resp.StatusCode >= 400:
		c.opts.Stats.Status4xx.Add(1)
	case resp.StatusCode >= 300:
		c.opts.Stats.Status3xx.Add(1)
	case resp.StatusCode >= 200:
		c.opts.Stats.Status2xx.Add(1)
	}
	c.debugf("%d %s (%d bytes, %s)", resp.StatusCode, u.Redacted(), len(body), time.Since(start).Round(time.Millisecond))
	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
		URL:        resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}, nil
}

// GetText is a convenience wrapper returning the body as a string.
func (c *Client) GetText(ctx context.Context, rawURL string, maxBody int64) (string, int, error) {
	resp, err := c.Get(ctx, rawURL, maxBody)
	if err != nil {
		return "", 0, err
	}
	return string(resp.Body), resp.StatusCode, nil
}

func retryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

func retryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrBodyTooLarge) || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// A per-request timeout is worth one more attempt at the caller level.
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := err.Error()
	for _, s := range []string{"connection reset", "connection refused", "broken pipe", "EOF", "tls:", "no such host", "i/o timeout", "server closed"} {
		if strings.Contains(strings.ToLower(msg), s) {
			return true
		}
	}
	return false
}

func backoff(attempt int) time.Duration {
	d := 250 * time.Millisecond
	for i := 1; i < attempt; i++ {
		d *= 2
		if d > 4*time.Second {
			d = 4 * time.Second
			break
		}
	}
	jitter := time.Duration(rand.Int63n(int64(200 * time.Millisecond)))
	return d + jitter
}

func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// BasicAuthHeader builds an Authorization header value.
func BasicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// rateLimiter is a token bucket shared by all workers.
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	rate   float64
	last   time.Time
}

func newRateLimiter(perSecond float64) *rateLimiter {
	burst := perSecond
	if burst < 1 {
		burst = 1
	}
	if burst > 1000 {
		burst = 1000
	}
	return &rateLimiter{tokens: burst, burst: burst, rate: perSecond, last: time.Now()}
}

func (l *rateLimiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.last).Seconds()
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
