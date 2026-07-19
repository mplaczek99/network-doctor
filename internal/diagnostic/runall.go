package diagnostic

import "context"

// RunAll executes the probe DAG headlessly with the same semantics as the TUI
// scheduler: every ready probe runs in parallel under its own ProbeTimeout, a
// failed or skipped prerequisite skips its dependents, and the egress
// downgrade is applied once every probe has a result.
func RunAll(ctx context.Context, probes []Probe) map[ProbeID]ProbeResult {
	results := make(map[ProbeID]ProbeResult, len(probes))
	started := make(map[ProbeID]bool, len(probes))
	done := make(chan ProbeResult)
	running := 0

	// Yes, this re-implements the ui scheduler's ready/blocked walk. No, don't
	// unify them: ui imports diagnostic, so sharing these ten lines means a
	// third package or an import cycle — steep rent for a DAG of ~10 nodes.
	//
	// schedule launches every probe whose deps all have results. Runs to a
	// fixpoint because starting one probe can make another ready — skips
	// cascade synchronously (a skip is a result too), so a chain of doomed
	// probes resolves in a single call without ever spawning a goroutine.
	schedule := func() {
		for progress := true; progress; {
			progress = false
			for _, p := range probes {
				if started[p.ID] {
					continue
				}
				// ready: all deps have results. blocked: at least one of
				// those results means this probe shouldn't bother trying.
				ready, blocked := true, false
				for _, d := range p.Deps {
					r, ok := results[d]
					if !ok {
						ready = false
						break
					}
					if r.Status == StatusFail || r.Status == StatusSkip {
						blocked = true
					}
				}
				if !ready {
					continue
				}
				started[p.ID] = true
				progress = true
				if blocked {
					results[p.ID] = ProbeResult{ID: p.ID, Status: StatusSkip, Detail: "skipped — a prerequisite failed"}
					continue
				}
				// Snapshot the dep results before spawning: the goroutine
				// must not touch the live results map, which this (single)
				// scheduling loop keeps mutating.
				deps := make(map[ProbeID]ProbeResult, len(p.Deps))
				for _, d := range p.Deps {
					deps[d] = results[d]
				}
				running++
				go func(p Probe, deps map[ProbeID]ProbeResult) {
					pctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
					defer cancel()
					res := p.Run(pctx, deps)
					res.ID = p.ID
					done <- res
				}(p, deps)
			}
		}
	}

	// Seed the roots, then drain: each finished probe may unlock more, so
	// reschedule after every receive. running is our only bookkeeping — when
	// it hits zero there's nothing in flight and nothing left to start, since
	// schedule already ran after the final result. Probes that time out still
	// send a result, so this can't hang; ctx cancellation just makes everyone
	// finish early and grumpy.
	schedule()
	for running > 0 {
		res := <-done
		results[res.ID] = res
		running--
		schedule()
	}
	DowngradeEgress(results)
	return results
}
