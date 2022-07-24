package apparmor

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

var qemuImgProfileTpl = template.Must(template.New("qemuImgProfile").Parse(`#include <tunables/global>
profile "{{ .name }}" flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  capability dac_override,
  capability dac_read_search,

  {{range $index, $element := .allowedCmdPaths}}
  	{{$element}} mixr,
  {{- end }}

  {{ .pathToImg }} rk,

  {{- if .dstPath }}
    {{ .dstPath }} rwk,
  {{- end }}
}
`))

type nullWriteCloser struct {
	*bytes.Buffer
}

func (nwc *nullWriteCloser) Close() error {
	return nil
}

func RunQemuImgWithApparmor(sysOS *sys.OS, cmd []string, imgPath string, dstPath string) (string, error) {
	allowedCmds := []string{"qemu-img"}
	//It is assumed that command starts with a program which sets resource limits, like prlimit or nice
	allowedCmds = append(allowedCmds, cmd[0])

	allowedCmdPaths := []string{}
	for _, c := range allowedCmds {
		cmdPath, err := exec.LookPath(c)
		if err != nil {
			return "", fmt.Errorf("Failed to start qemu-img: Failed to find executable: %w", err)
		}

		allowedCmdPaths = append(allowedCmdPaths, cmdPath)
	}

	err := qemuImgProfileLoad(sysOS, imgPath, dstPath, allowedCmdPaths)
	if err != nil {
		return "", fmt.Errorf("Failed to start extract: Failed to load profile: %w", err)
	}

	defer func() { _ = qemuImgDelete(sysOS, imgPath) }()
	defer func() { _ = qemuImgUnload(sysOS, imgPath) }()

	var buffer bytes.Buffer
	var output bytes.Buffer
	p, err := subprocess.NewProcessWithFds(cmd[0], cmd[1:], nil, &nullWriteCloser{&output}, &nullWriteCloser{&buffer})
	if err != nil {
		return "", fmt.Errorf("Failed to start extract: Failed to creating subprocess: %w", err)
	}

	p.SetApparmor(qemuImgProfileName(imgPath))

	err = p.Start()
	if err != nil {
		return "", fmt.Errorf("Failed to start extract: Failed running: qemu-img: %w", err)
	}

	_, err = p.Wait(context.Background())
	if err != nil {
		return "", shared.RunError{
			Msg:    fmt.Sprintf("Failed to run: %s %s: %s", cmd, strings.Join(cmd, " "), strings.TrimSpace(buffer.String())),
			Stderr: buffer.String(),
			Err:    err,
		}
	}

	return output.String(), nil
}

// qemuImgProfileLoad ensures that the qemu-img's policy is loaded into the kernel.
func qemuImgProfileLoad(sysOS *sys.OS, imgPath string, dstPath string, allowedCmdPaths []string) error {
	profile := filepath.Join(aaPath, "profiles", qemuImgProfileFilename(imgPath))
	content, err := ioutil.ReadFile(profile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	updated, err := qemuImgProfile(imgPath, dstPath, allowedCmdPaths)
	if err != nil {
		return err
	}

	if string(content) != string(updated) {
		err = ioutil.WriteFile(profile, []byte(updated), 0600)
		if err != nil {
			return err
		}
	}

	err = loadProfile(sysOS, qemuImgProfileFilename(imgPath))
	if err != nil {
		return err
	}

	return nil
}

// qemuImgUnload ensures that the qemu-img's policy namespace is unloaded to free kernel memory.
// This does not delete the policy from disk or cache.
func qemuImgUnload(sysOS *sys.OS, imgPath string) error {
	err := unloadProfile(sysOS, qemuImgProfileName(imgPath), qemuImgProfileFilename(imgPath))
	if err != nil {
		return err
	}

	return nil
}

// qemuImgDelete removes the profile from cache/disk.
func qemuImgDelete(sysOS *sys.OS, imgPath string) error {
	return deleteProfile(sysOS, qemuImgProfileName(imgPath), qemuImgProfileFilename(imgPath))
}

// qemuImgProfile generates the AppArmor profile template from the given destination path.
func qemuImgProfile(imgPath string, dstPath string, allowedCmdPaths []string) (string, error) {
	// Render the profile.
	var sb *strings.Builder = &strings.Builder{}
	err := qemuImgProfileTpl.Execute(sb, map[string]any{
		"name":            qemuImgProfileName(imgPath),
		"pathToImg":       imgPath,
		"dstPath":         dstPath,
		"allowedCmdPaths": allowedCmdPaths,
	})
	if err != nil {
		return "", err
	}

	return sb.String(), nil
}

// qemuImgProfileName returns the AppArmor profile name.
func qemuImgProfileName(outputPath string) string {
	return getProfileName(outputPath)
}

// qemuImgProfileFilename returns the name of the on-disk profile name.
func qemuImgProfileFilename(outputPath string) string {
	return getProfileName(outputPath)
}

func getProfileName(outputPath string) string {
	name := strings.Replace(strings.Trim(outputPath, "/"), "/", "-", -1)
	return profileName("qemu-img", name)
}
