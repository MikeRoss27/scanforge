package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/ui"
	"github.com/MikeRoss27/scanforge/internal/version"
)

const updateModulePath = "github.com/MikeRoss27/scanforge"

type UpdateOptions struct {
	Tools bool
}

// moduleInfo is the subset of `go list -m -json` output we need.
type moduleInfo struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

func (a *App) Update(ctx context.Context, opts UpdateOptions) error {
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("the 'go' command was not found in PATH, which is required for updating: %w", err)
	}

	latest, err := latestVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve the latest scanforge version: %w", err)
	}

	if version.Version == strings.TrimPrefix(latest.Version, "v") && version.Commit != "dev" {
		ui.Info("ScanForge is already up to date (%s).", latest.Version)
		return a.updateTools(ctx, opts)
	}

	ui.Info("Updating scanforge %s -> %s ...", version.Version, latest.Version)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate the running scanforge binary: %w", err)
	}
	dest, err := installDest(ctx, exe)
	if err != nil {
		return err
	}
	if err := buildBinary(ctx, latest, dest); err != nil {
		return err
	}

	if filepath.Dir(dest) != filepath.Dir(exe) {
		ui.Warn("Installed to %s, but the running binary lives in %s. Add %s to your PATH or move the binary.",
			dest, filepath.Dir(exe), filepath.Dir(dest))
	}
	ui.Success("ScanForge updated to %s (%s).", latest.Version, dest)

	return a.updateTools(ctx, opts)
}

// latestVersion resolves the newest tagged release of the module through the
// Go module proxy (same resolution `go install @latest` would use).
func latestVersion(ctx context.Context) (moduleInfo, error) {
	out, err := exec.CommandContext(ctx, "go", "list", "-m", "-json", updateModulePath+"@latest").Output()
	if err != nil {
		return moduleInfo{}, err
	}
	var info moduleInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return moduleInfo{}, err
	}
	if info.Version == "" {
		return moduleInfo{}, fmt.Errorf("no version reported for %s@latest", updateModulePath)
	}
	return info, nil
}

// installDest returns where the new binary should be written: the directory of
// the running executable when writable, otherwise $GOBIN (or $GOPATH/bin).
func installDest(ctx context.Context, exe string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if isWritableDir(filepath.Dir(exe)) {
		return filepath.Join(filepath.Dir(exe), binaryName()), nil
	}
	binDir, err := goBinDir(ctx)
	if err != nil {
		return "", fmt.Errorf("cannot write next to the running binary (%s) and cannot locate GOBIN: %w", exe, err)
	}
	return filepath.Join(binDir, binaryName()), nil
}

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "scanforge.exe"
	}
	return "scanforge"
}

func isWritableDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".scanforge-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func goBinDir(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOBIN").Output()
	if err != nil {
		return "", err
	}
	if bin := strings.TrimSpace(string(out)); bin != "" {
		return bin, nil
	}
	out, err = exec.CommandContext(ctx, "go", "env", "GOPATH").Output()
	if err != nil {
		return "", err
	}
	if gopath := strings.TrimSpace(string(out)); gopath != "" {
		return filepath.Join(gopath, "bin"), nil
	}
	return "", fmt.Errorf("neither GOBIN nor GOPATH is set")
}

// buildBinary installs the given module version with the same ldflags as
// release builds (version/commit/date metadata), then moves the binary into
// place at dest. A plain `go install` would produce a binary reporting
// version 0.0.1/dev, so the metadata must be injected explicitly.
func buildBinary(ctx context.Context, info moduleInfo, dest string) error {
	commit, err := resolveCommit(ctx, info.Version)
	if err != nil {
		ui.Warn("Could not resolve the commit for %s: %v", info.Version, err)
		commit = "unknown"
	}
	date := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	ldflags := fmt.Sprintf(
		"-s -w -X github.com/MikeRoss27/scanforge/internal/version.Version=%s -X github.com/MikeRoss27/scanforge/internal/version.Commit=%s -X github.com/MikeRoss27/scanforge/internal/version.Date=%s",
		strings.TrimPrefix(info.Version, "v"), commit, date)

	cmd := exec.CommandContext(ctx, "go", "install",
		"-ldflags", ldflags,
		updateModulePath+"/cmd/scanforge@"+info.Version)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build scanforge %s: %w", info.Version, err)
	}

	binDir, err := goBinDir(ctx)
	if err != nil {
		return err
	}
	built := filepath.Join(binDir, binaryName())
	if err := moveFile(built, dest); err != nil {
		return fmt.Errorf("failed to install the new binary at %s: %w", dest, err)
	}
	return nil
}

// resolveCommit returns the short commit hash a release tag points to,
// preferring the peeled (annotated tag) ref.
func resolveCommit(ctx context.Context, tag string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "ls-remote", "https://"+updateModulePath,
		"refs/tags/"+tag+"^{}", "refs/tags/"+tag).Output()
	if err != nil {
		return "", err
	}
	short := func(sha string) string {
		if len(sha) > 7 {
			return sha[:7]
		}
		return sha
	}
	var peeled, plain string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if strings.HasSuffix(fields[1], "^{}") {
			peeled = fields[0]
		} else {
			plain = fields[0]
		}
	}
	switch {
	case peeled != "":
		return short(peeled), nil
	case plain != "":
		return short(plain), nil
	default:
		return "", fmt.Errorf("tag %s not found in https://%s", tag, updateModulePath)
	}
}

// moveFile renames src over dest, falling back to a copy when the rename
// crosses filesystems or is otherwise refused.
func moveFile(src, dest string) error {
	if err := os.Rename(src, dest); err == nil {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0o755); err != nil {
		return err
	}
	return os.Remove(src)
}

func (a *App) updateTools(ctx context.Context, opts UpdateOptions) error {
	if !opts.Tools {
		return nil
	}
	tools := []string{
		"github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		"github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		"github.com/projectdiscovery/httpx/cmd/httpx@latest",
		"github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		"github.com/projectdiscovery/katana/cmd/katana@latest",
		"github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		"github.com/ffuf/ffuf/v2@latest",
	}
	fmt.Println()
	ui.Info("Updating external tools...")
	for _, tool := range tools {
		ui.Info("Updating %s ...", tool)
		tcmd := exec.CommandContext(ctx, "go", "install", tool)

		if err := tcmd.Run(); err != nil {
			ui.Warn("Failed to update %s: %v", tool, err)
		} else {
			ui.Success("Updated %s", tool)
		}
	}
	ui.Success("External tools updated.")
	return nil
}
