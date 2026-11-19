package safecore

import "time"

// All transitions are explicitly allowed; an interrupted attempt does not get
// reclassified as success. A retry needs a newly confirmed uninstall session.
func ValidTargetState(s string) bool {
	switch s {
	case "pending", "running", "verified", "reboot_pending", "blocked", "failed":
		return true
	default:
		return false
	}
}
func ValidTransition(from, to string) bool {
	if from == "pending" && to == "running" {
		return true
	}
	if from == "running" {
		switch to {
		case "verified", "reboot_pending", "blocked", "failed":
			return true
		}
	}
	return false
}

// Tick-based timestamps are approximate; compare a boot session against the
// previous one, and require that the new boot happened after the session began.
// This deliberately errs on the side of requiring another reboot.
func RebootAfter(started, before, after time.Time) bool {
	if started.IsZero() || before.IsZero() || after.IsZero() {
		return false
	}
	return after.Sub(before) > 30*time.Second && after.After(started.Add(-30*time.Second))
}
