package app

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"gitleak/internal/httpc"
	"gitleak/internal/ui"
)

// ScanOptions configures a bulk scan.
type ScanOptions struct {
	Workers int
	Extra   bool
	OutRoot string
}

// Scan probes every target concurrently and returns results in input order.
func Scan(ctx context.Context, c *httpc.Client, targets []Target, bc *baselineCache, u *ui.UI, opts ScanOptions) []*TargetResult {
	results := make([]*TargetResult, len(targets))
	if len(targets) == 0 {
		return results
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = 32
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	start := time.Now()
	var processed atomic.Int64
	var found atomic.Int64
	var stopProgress chan struct{}
	var pwg sync.WaitGroup
	if u != nil {
		stopProgress = make(chan struct{})
		pwg.Add(1)
		go func() {
			defer pwg.Done()
			tk := time.NewTicker(2 * time.Second)
			defer tk.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-tk.C:
					st := c.Stats().Snapshot()
					elapsed := time.Since(start).Seconds()
					rps := 0.0
					if elapsed > 0 {
						rps = float64(st.Requests) / elapsed
					}
					u.Progress("scan %d/%d  found=%d  req=%d  %.0f req/s  err=%d",
						processed.Load(), len(targets), found.Load(), st.Requests, rps, st.Errors)
				}
			}
		}()
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					continue
				}
				t := targets[idx]
				det := Detect(ctx, c, t, bc, false)
				if !det.Vulnerable && det.NetworkErr && !t.ExplicitScheme {
					alt := t.WithScheme("http")
					if det2 := Detect(ctx, c, alt, bc, false); det2.Vulnerable {
						det = det2
					}
				}
				if det.Vulnerable && opts.Extra {
					det.DetectExtra(ctx, c)
				}
				if det.Vulnerable {
					if id, ref, rerr := resolveHeadID(ctx, c, det); rerr == nil {
						det.HeadObject = id.String()
						if ref != "" {
							det.HeadRef = ref
						}
					}
				}
				res := newTargetResult(det)
				res.ElapsedMS = det.Elapsed.Milliseconds()
				if det.Vulnerable && opts.OutRoot != "" {
					res.OutDir = filepath.Join(opts.OutRoot, det.Target.Slug())
				}
				results[idx] = res
				if det.Vulnerable {
					found.Add(1)
				}
				processed.Add(1)
			}
		}()
	}
	for i := range targets {
		select {
		case <-ctx.Done():
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	if stopProgress != nil {
		close(stopProgress)
		pwg.Wait()
		u.ClearProgress()
	}
	return results
}
