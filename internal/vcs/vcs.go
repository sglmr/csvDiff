package vcs

import (
	"fmt"
	"runtime/debug"
)

func Version() string {
	var modified bool
	var revision string
	var time string

	// Get the build info from the currently running binary
	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					modified = true
				}
			case "vcs.time":
				time = s.Value
			}
		}
	}
	if revision == "" {
		return "unavailable"
	}

	if modified {
		return fmt.Sprintf("%s-%s+dirty", time, revision)
	}

	return fmt.Sprintf("%s-%s", time, revision)
}
