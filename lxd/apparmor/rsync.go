//go:build linux && cgo && !agent

package apparmor

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/lxc/lxd/lxd/sys"
	"github.com/lxc/lxd/shared"
	"github.com/lxc/lxd/shared/subprocess"
)

var rsyncProfileTpl = template.Must(template.New("rsyncProfile").Parse(`#include <tunables/global>
profile "{{ .name }}" flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  capability dac_override,
  capability dac_read_search,
  capability mknod,
  capability chown,
  capability fsetid,
  capability fowner,

  unix, # TODO Perhaps a stricter restriction can be made here
  
  @{PROC}/@{pid}/cmdline r,
  @{PROC}/@{pid}/cpuset r,
  {{ .rootPath }}/{etc,lib,usr/lib}/os-release r,

  {{ .logPath }}/*/netcat.log rw,

  {{ .rootPath }}/run/{resolvconf,NetworkManager,systemd/resolve,connman,netconfig}/resolv.conf r,
  {{ .rootPath }}/run/systemd/resolve/stub-resolv.conf r,

{{range $index, $element := .allowedCmdPaths}}
  {{$element}} mixr,
{{- end }}

  {{ .sourcePath }}/** r,
  {{ .sourcePath }}/ r,


{{- if .dstPath }}
  {{ .dstPath }}/** rw,
  {{ .dstPath }}/ rw,
{{- end }}

{{- if .snap }}
  # Snap-specific libraries
  /snap/lxd/*/lib/**.so* mr,

  /var/snap/lxd/common/lxd.debug mixr,
{{- end }}

{{if .libraryPath -}}
  # Entries from LD_LIBRARY_PATH
{{range $index, $element := .libraryPath}}
  {{$element}}/** mr,
{{- end }}
{{- end }}

  deny /sys/devices/virtual/dmi/id/product_uuid r,
}
`))

func Rsync(sysOS *sys.OS, cmd []string, sourcePath string, dstPath string) (string, error) {
	//It is assumed that command starts with a program which sets resource limits, like prlimit or nice
	allowedCmds := []string{"rsync"}

	allowedCmdPaths := []string{}
	for _, c := range allowedCmds {
		cmdPath, err := exec.LookPath(c)
		if err != nil {
			return "", fmt.Errorf("Failed to find executable %q: %w", c, err)
		}

		allowedCmdPaths = append(allowedCmdPaths, cmdPath)
	}

	// Attempt to deref all paths.
	imgFullPath, err := filepath.EvalSymlinks(sourcePath)
	if err == nil {
		sourcePath = imgFullPath
	}

	if dstPath != "" {
		dstFullPath, err := filepath.EvalSymlinks(dstPath)
		if err == nil {
			dstPath = dstFullPath
		}
	}

	err = rsyncProfileLoad(sysOS, sourcePath, dstPath, allowedCmdPaths)
	if err != nil {
		return "", fmt.Errorf("Failed to load rsync profile: %w", err)
	}

	defer func() {
		_ = rsyncUnload(sysOS, sourcePath)
		_ = rsyncDelete(sysOS, sourcePath)
	}()

	var buffer bytes.Buffer
	var output bytes.Buffer

	p := subprocess.NewProcessWithFds("rsync", cmd, nil, &nullWriteCloser{&output}, &nullWriteCloser{&buffer})
	if err != nil {
		return "", fmt.Errorf("Failed creating rsync subprocess: %w", err)
	}

	p.SetApparmor(rsyncProfileName(sourcePath))

	err = p.Start(context.Background())
	if err != nil {
		return "", fmt.Errorf("Failed running rsync: %w", err)
	}

	_, err = p.Wait(context.Background())
	if err != nil {
		return "", shared.NewRunError(cmd[0], cmd[1:], err, nil, &buffer)
	}

	return output.String(), nil
}

func rsyncProfileLoad(sysOS *sys.OS, sourcePath string, dstPath string, allowedCmdPaths []string) error {
	profile := filepath.Join(aaPath, "profiles", rsyncProfileFilename(sourcePath))
	content, err := ioutil.ReadFile(profile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	updated, err := rsyncProfile(sourcePath, dstPath, allowedCmdPaths)
	if err != nil {
		return err
	}

	if string(content) != string(updated) {
		err = ioutil.WriteFile(profile, []byte(updated), 0600)
		if err != nil {
			return err
		}
	}

	err = loadProfile(sysOS, rsyncProfileFilename(sourcePath))

	return err
}

// This does not delete the policy from disk or cache.
func rsyncUnload(sysOS *sys.OS, sourcePath string) error {
	return unloadProfile(sysOS, rsyncProfileName(sourcePath), rsyncProfileFilename(sourcePath))
}

// This removes the profile from cache/disk.
func rsyncDelete(sysOS *sys.OS, sourcePath string) error {
	return deleteProfile(sysOS, rsyncProfileName(sourcePath), rsyncProfileFilename(sourcePath))
}

// rsyncProfile generates the AppArmor profile template from the given destination path.
func rsyncProfile(sourcePath string, dstPath string, allowedCmdPaths []string) (string, error) {
	// Render the profile.
	rootPath := ""
	if shared.InSnap() {
		rootPath = "/var/lib/snapd/hostfs"
	}

	logPath := shared.LogPath("")

	var sb *strings.Builder = &strings.Builder{}
	err := rsyncProfileTpl.Execute(sb, map[string]any{
		"name":            rsyncProfileName(sourcePath),
		"sourcePath":      sourcePath,
		"dstPath":         dstPath,
		"allowedCmdPaths": allowedCmdPaths,
		"snap":            shared.InSnap(),
		"rootPath":        rootPath,
		"logPath":         logPath,
		"libraryPath":     strings.Split(os.Getenv("LD_LIBRARY_PATH"), ":"),
	})
	if err != nil {
		return "", err
	}

	return sb.String(), nil
}

// rsyncProfileName returns the AppArmor profile name.
func rsyncProfileName(outputPath string) string {
	return GetRsyncProfileName(outputPath)
}

// rsyncProfileFilename returns the name of the on-disk profile name.
func rsyncProfileFilename(outputPath string) string {
	return GetRsyncProfileName(outputPath)
}

func GetRsyncProfileName(outputPath string) string {
	name := strings.Replace(strings.Trim(outputPath, "/"), "/", "-", -1)
	return profileName("rsync", name)
}

func RsyncProfileLoad(sysOS *sys.OS, sourcePath string, dstPath string, allowedCmdPaths []string) error {
	return rsyncProfileLoad(sysOS, sourcePath, dstPath, allowedCmdPaths)
}

func RsyncProfileUnload(sysOS *sys.OS, sourcePath string) error {
	return rsyncUnload(sysOS, sourcePath)
}

func RsyncProfileDelete(sysOS *sys.OS, sourcePath string) error {
	return rsyncDelete(sysOS, sourcePath)
}
