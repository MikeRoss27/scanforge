package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/wpdetect"
	"github.com/MikeRoss27/scanforge/internal/ui"
	"golang.org/x/term"
)

// wpProbeTimeout bounds the pre-scan WordPress suggestion probe: it must
// never make the operator wait noticeably before the real scan starts.
const wpProbeTimeout = 8 * time.Second

// WPPrompter is injectable so the suggestion can be tested without a real
// terminal, mirroring ScopePrompter.
type WPPrompter interface {
	IsTTY() bool
	Confirm(target, confidence string) (bool, error)
}

type terminalWPPrompter struct {
	input  *os.File
	output io.Writer
}

func newTerminalWPPrompter() WPPrompter {
	return &terminalWPPrompter{input: os.Stdin, output: os.Stderr}
}

func (p *terminalWPPrompter) IsTTY() bool {
	return p != nil && p.input != nil && term.IsTerminal(int(p.input.Fd()))
}

func (p *terminalWPPrompter) Confirm(target, confidence string) (bool, error) {
	if p == nil || p.input == nil {
		return false, fmt.Errorf("WordPress suggestion input is unavailable")
	}
	_, _ = fmt.Fprintln(p.output, ui.Secondary(fmt.Sprintf("WordPress detected on %s (confidence: %s)", target, confidence)))
	_, _ = fmt.Fprintln(p.output)
	_, _ = fmt.Fprint(p.output, ui.Bold("Enable --wp for this run?")+" [y/N] › ")

	answer, err := bufio.NewReader(p.input).ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false, fmt.Errorf("read WordPress suggestion confirmation: %w", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

// maybeSuggestWordPress runs the same couple of passive requests wpdetect
// itself makes (generator meta, feed, readme.html, REST index) against the
// confirmed target, and if it looks like WordPress, offers to layer --wp
// onto this run. It is advisory, not a safety gate like scope confirmation:
// without a TTY (CI, scripts) it just notes the detection and continues
// unchanged rather than blocking or silently changing behavior.
//
// Must only be called after scope is confirmed — this is live network
// traffic against the target, same as every other module's first request.
func (a *App) maybeSuggestWordPress(opts RunOptions, moduleNames []string) []string {
	if opts.WP || opts.DryRun {
		return moduleNames
	}

	target := opts.Target
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}

	client, closeConn, err := modules.NewProxyClient(opts.Proxy, wpProbeTimeout)
	if err != nil {
		return moduleNames
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), wpProbeTimeout)
	defer cancel()

	runCtx := modules.NewRunContext(opts.Target, "", false, nil)
	runCtx.Headers = opts.Headers
	finding := wpdetect.ProbeHost(ctx, client, runCtx, target)
	if !finding.IsWordPress {
		return moduleNames
	}

	if a.WPPrompter == nil || !a.WPPrompter.IsTTY() {
		_, _ = fmt.Fprintln(os.Stderr, ui.Secondary(fmt.Sprintf(
			"WordPress detected on %s (confidence: %s); re-run with --wp for the full WordPress engagement chain", target, finding.Confidence)))
		return moduleNames
	}
	accepted, err := a.WPPrompter.Confirm(target, finding.Confidence)
	if err != nil || !accepted {
		return moduleNames
	}
	return applyWordPress(moduleNames, true, opts.WordPress.Bruteforce)
}
