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
	schedule := func() {
		for progress := true; progress; {
			progress = false
			for _, p := range probes {
				if started[p.ID] {
					continue
				}
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
