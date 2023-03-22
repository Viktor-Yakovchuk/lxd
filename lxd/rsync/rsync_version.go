package rsync

import (
	"strings"

	"github.com/lxc/lxd/shared"
	"github.com/lxc/lxd/shared/version"
)

// AtLeast compares the local version to a minimum version.
func AtLeast(min string) bool {
	// Parse the current version.
	out, err := shared.RunCommand("rsync", "--version")
	if err != nil {
		return false
	}

	fields := strings.Split(strings.Split(out, "\n")[0], "  ")
	if len(fields) < 3 {
		return false
	}

	versionStr := strings.TrimPrefix(fields[1], "version ")

	ver, err := version.Parse(versionStr)
	if err != nil {
		return false
	}

	// Load minium version.
	minVer, err := version.NewDottedVersion(min)
	if err != nil {
		return false
	}

	return ver.Compare(minVer) >= 0
}
