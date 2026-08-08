package jsverify

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

const (
	// settleTimeout is how long a replay waits for the sink to fire after the
	// page loaded and the attack sources were dispatched. Polling stops as
	// soon as the payload executes, so confirmed findings return early.
	settleTimeout = 8 * time.Second
	// markerPrefix identifies payloads that have been rewritten with a unique
	// run id; the hooks look for it in sink assignments.
	markerPrefix = "__SF__"
)

// paramNames are the URL parameter names attacked with the payload. Real
// applications read a handful of common names into sinks (search boxes,
// redirects, message relays), so a small curated set keeps URL length sane
// while covering the usual suspects.
var paramNames = []string{"q", "url", "data", "redirect", "next", "src", "msg"}

// alertCall matches alert(...) calls so payloads can be rewritten to fire
// dialogs carrying the unique marker.
var alertCall = regexp.MustCompile(`alert\s*\([^)]*\)`)

// hooks is injected before any page script on every navigation. It records
// every sink assignment whose value contains the marker into window.__sf,
// which the verifier reads back after the attack sources were dispatched.
const hooks = `
window.__sf = { hits: [], skip: false };
(function () {
  var mk = function (v) {
    try {
      var s = (typeof v === 'string') ? v : JSON.stringify(v);
      if (s.indexOf('__SF__') !== -1) { window.__sf.hits.push(s.slice(0, 200)); }
    } catch (e) {}
  };
  var wrapSetter = function (proto, prop) {
    try {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) { return; }
      Object.defineProperty(proto, prop, {
        configurable: true,
        get: d.get,
        set: function (v) { mk(v); return d.set.call(this, v); }
      });
    } catch (e) {}
  };
  wrapSetter(Element.prototype, 'innerHTML');
  wrapSetter(Element.prototype, 'outerHTML');
  wrapSetter(HTMLIFrameElement.prototype, 'srcdoc');
  try {
    var dw = document.write.bind(document);
    document.write = function () {
      for (var i = 0; i < arguments.length; i++) { mk(arguments[i]); }
      return dw.apply(document, arguments);
    };
  } catch (e) {}
  try {
    var oe = window.eval;
    window.eval = function (s) { mk(s); return oe(s); };
  } catch (e) {}
  try {
    var wp = window.postMessage.bind(window);
    window.postMessage = function (m, o) {
      if (!window.__sf.skip) { mk(m); }
      return wp(m, o);
    };
    var pp = window.parent.postMessage.bind(window.parent);
    window.parent.postMessage = function (m, o) {
      if (!window.__sf.skip) { mk(m); }
      return pp(m, o);
    };
  } catch (e) {}
})();
`

// attackURLs builds the variants loaded during one replay: the page with the
// payload in URL parameters, then with the payload in the fragment.
func attackURLs(pageURL, payload string) []string {
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var variants []string

	withParams := *parsed
	q := withParams.Query()
	for _, name := range paramNames {
		q.Set(name, payload)
	}
	withParams.RawQuery = q.Encode()
	withParams.Fragment = ""
	variants = append(variants, withParams.String())

	withHash := *parsed
	withHash.RawQuery = ""
	withHash.Fragment = payload
	variants = append(variants, withHash.String())

	return variants
}

// markPayload rewrites a library payload so its effects carry the unique run
// marker: alert(...) arguments become alert("__SF__<id>"), and bare URL
// payloads get the marker appended as a fragment.
func markPayload(payload string, id int) string {
	marker := fmt.Sprintf("%s%d", markerPrefix, id)
	marked := alertCall.ReplaceAllString(payload, fmt.Sprintf("alert(%q)", marker))
	if marked != payload {
		return marked
	}
	if strings.HasPrefix(payload, "http") && !strings.Contains(payload, "#") {
		return payload + "#" + marker
	}
	return marked
}

// chromiumLaunchCommand mirrors the exact browser invocation chromedp will
// start: the binary and every flag passed to the exec allocator. chromedp
// spawns the process itself, so the runner never sees it; recording the real
// command line keeps the audit trail faithful instead of a placeholder.
func chromiumLaunchCommand(browser string, proxy string) runner.Command {
	args := []string{"--headless", "--no-sandbox", "--disable-gpu"}
	if proxy != "" {
		args = append(args, "--proxy-server="+proxy)
	}
	return runner.Command{
		Name: browser,
		Args: args,
	}
}

// verifyAll replays every finding in one shared browser instance, one page
// load per finding, and returns the verdicts in input order. A browser that
// fails to start is a module-level error (returned, and therefore audited),
// not a sequence of identical per-finding "unreachable" verdicts.
func verifyAll(ctx context.Context, runCtx *modules.RunContext, browser string, findings []finding, pages map[string]string) ([]verdict, error) {
	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(browser),
		chromedp.Headless,
		chromedp.NoSandbox,
		chromedp.DisableGPU,
	}
	if runCtx.Proxy != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(runCtx.Proxy))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	// Force the browser to actually start before replaying anything: a
	// broken binary or a wedged X server surfaces here with the underlying
	// error (including the OS exit status) instead of failing every replay.
	if err := chromedp.Run(browserCtx, chromedp.Navigate("about:blank")); err != nil {
		return nil, fmt.Errorf("browser failed to start: %w", err)
	}

	results := make([]verdict, 0, len(findings))
	for i, item := range findings {
		payload := markPayload(item.Payloads[0], i)
		pageURL := pages[originOf(item.URL)]
		if pageURL == "" {
			pageURL = originOf(item.URL) + "/"
		}
		results = append(results, replayOne(browserCtx, item, pageURL, payload))
	}
	return results, nil
}

func originOf(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// dialogCapture collects the message of every alert() fired by the replayed
// page and dismisses the dialogs so page scripts never block. The chromedp
// target listener runs on its own goroutine while settle polls, so all access
// is mutex-protected; pending dismissals are tracked so replayOne can wait for
// them before tearing the tab down.
type dialogCapture struct {
	mu  sync.Mutex
	msg string
	wg  sync.WaitGroup
}

// handle records the first dialog message and dismisses the dialog in the
// background. Dismissal must not run on the listener goroutine (it would
// deadlock chromedp), so it is tracked and awaited before the tab closes.
func (c *dialogCapture) handle(tabCtx context.Context, message string) {
	c.mu.Lock()
	if c.msg == "" {
		c.msg = message
	}
	c.wg.Add(1)
	c.mu.Unlock()

	go func() {
		defer c.wg.Done()
		_ = chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			return page.HandleJavaScriptDialog(false).Do(ctx)
		}))
	}()
}

func (c *dialogCapture) message() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.msg
}

// waitForDismissals waits for pending dialog dismissals with a short upper
// bound so a wedged renderer cannot stall the whole replay.
func (c *dialogCapture) waitForDismissals() {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

// replayOne drives a single payload against one page and returns the verdict.
func replayOne(browserCtx context.Context, item finding, pageURL, payload string) verdict {
	out := verdict{
		URL:      item.URL,
		Page:     pageURL,
		Kind:     item.Kind,
		Pattern:  item.Pattern,
		Severity: item.Severity,
		Payload:  payload,
		Verdict:  "not-observed",
	}

	tabCtx, tabCancel := chromedp.NewContext(browserCtx)
	defer tabCancel()

	var capture dialogCapture
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if dlg, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			// Dismissing unblocks the page; the recorded message is what we
			// check, and confirm()/prompt() variants would wait forever.
			capture.handle(tabCtx, dlg.Message)
		}
	})
	defer capture.waitForDismissals()

	installErr := chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(hooks).Do(ctx)
		return err
	}))
	if installErr != nil {
		out.Verdict = "unreachable"
		out.Evidence = "failed to install hooks: " + installErr.Error()
		return out
	}

	if err := chromedp.Run(tabCtx, chromedp.Navigate(pageURL)); err != nil {
		out.Verdict = "unreachable"
		out.Evidence = err.Error()
		return out
	}

	// Object literals are dispatched as parsed data (the realistic attack);
	// everything else travels as a quoted string message. The skip flag stops
	// our own dispatch from being recorded as a sink hit by the hooks.
	postMessageExpr := strconv.Quote(payload)
	if strings.HasPrefix(payload, "{") {
		postMessageExpr = payload
	}
	attackJS := fmt.Sprintf(
		"window.__sf.skip = true; window.postMessage(%s, \"*\"); window.postMessage(%s, window.location.origin); window.__sf.skip = false;",
		postMessageExpr, postMessageExpr,
	)

	for _, variant := range attackURLs(pageURL, payload) {
		if err := chromedp.Run(tabCtx,
			chromedp.Navigate(variant),
			chromedp.Evaluate(attackJS, nil),
		); err != nil {
			continue
		}
		if v := settle(tabCtx, &capture, payload); v != "" {
			markVerdict(&out, v)
			if out.Verdict == "executed" {
				return out
			}
		}
	}

	// A payload assigned to location navigates the tab itself. Detect that
	// by checking the final URL carries the marker WITHOUT being one of the
	// variants we loaded ourselves (our own fragment/params would match).
	if final := currentURL(tabCtx); final != "" && strings.Contains(final, markerPrefix) && !isOurVariant(pageURL, payload, final) {
		markVerdict(&out, "sink-reached")
		out.Evidence = "page navigated to " + final
	}
	return out
}

// currentURL reads the tab's location; empty on error.
func currentURL(tabCtx context.Context) string {
	var url string
	if err := chromedp.Run(tabCtx, chromedp.Evaluate(`document.URL`, &url)); err != nil {
		return ""
	}
	return url
}

// isOurVariant reports whether final is exactly one of the attack URLs this
// replay loaded (same origin/path with our fragment or our param payloads).
// Paths are compared after stripping the trailing slash: browsers normalize
// "https://host/#frag" to "https://host#frag" during navigation.
func isOurVariant(pageURL, payload, final string) bool {
	base, err := url.Parse(pageURL)
	if err != nil {
		return false
	}
	got, err := url.Parse(final)
	if err != nil {
		return false
	}
	if got.Scheme != base.Scheme || got.Host != base.Host ||
		strings.TrimRight(got.Path, "/") != strings.TrimRight(base.Path, "/") {
		return false
	}
	// Hash variant: fragment equals the raw payload.
	if payload != "" && got.Fragment != "" {
		decoded, err := url.QueryUnescape(got.Fragment)
		if err == nil && (decoded == payload || got.Fragment == payload) {
			return true
		}
	}
	// Params variant: query contains all injected names with the payload.
	q := got.Query()
	injected := 0
	for _, name := range paramNames {
		if q.Get(name) == payload {
			injected++
		}
	}
	return injected > 0
}

// settle polls the hooks and the dialog capture until the marker shows up or
// the timeout expires. It returns "executed" when the payload ran JavaScript
// (dialog with marker), "sink-reached" when a monitored sink received the
// marker, and an empty string when nothing fired.
func settle(tabCtx context.Context, capture *dialogCapture, payload string) string {
	deadline := time.Now().Add(settleTimeout)
	var sf struct {
		Hits []string `json:"hits"`
	}
	for time.Now().Before(deadline) {
		if strings.Contains(capture.message(), markerPrefix) {
			return "executed"
		}
		sf.Hits = nil
		if err := chromedp.Run(tabCtx, chromedp.Evaluate(`window.__sf`, &sf)); err == nil {
			for _, hit := range sf.Hits {
				if strings.Contains(hit, markerPrefix) {
					return "sink-reached"
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return ""
}

func markVerdict(out *verdict, verdict string) {
	if out.Verdict == "executed" {
		return
	}
	out.Verdict = verdict
	if verdict == "executed" {
		out.Evidence = "payload executed JavaScript (alert dialog with marker)"
	}
}

// detectBrowser looks for a usable chrome-family executable: SCANFORGE_CHROME
// first, then the common distro installs and portable builds on PATH. The
// configured tools.chromium path takes precedence elsewhere.
func detectBrowser() string {
	if env := os.Getenv("SCANFORGE_CHROME"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome-headless-shell"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}
