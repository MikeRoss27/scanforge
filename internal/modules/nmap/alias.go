package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
)

var (
	hostnamesBlock = regexp.MustCompile(`(?s)<hostnames>.*?</hostnames>`)
	hostnamesEmpty = regexp.MustCompile(`<hostnames\s*/>`)
	addressTagEnd  = regexp.MustCompile(`<address[^>]*/>`)
)

// rewriteHostnameXML returns nmap's XML output with its <hostnames> block
// replaced by a single entry for alias. nmap's own XML always describes
// the IP it actually scanned; when that scan was shared by several
// hostnames (see groupTargets), each alias gets a copy of the real result
// with only this block changed, so the report engine still creates one
// accurate asset per hostname instead of just the leader's.
func rewriteHostnameXML(doc []byte, alias string) []byte {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(alias))
	replacement := []byte(fmt.Sprintf(`<hostnames><hostname name="%s" type="user"/></hostnames>`, escaped.String()))

	switch {
	case hostnamesBlock.Match(doc):
		return hostnamesBlock.ReplaceAll(doc, replacement)
	case hostnamesEmpty.Match(doc):
		return hostnamesEmpty.ReplaceAll(doc, replacement)
	}
	// No hostnames element at all (e.g. the leader itself was an IP
	// literal): insert one right after the host's address so the alias
	// still gets its own name instead of silently falling back to the IP.
	if loc := addressTagEnd.FindIndex(doc); loc != nil {
		out := make([]byte, 0, len(doc)+len(replacement))
		out = append(out, doc[:loc[1]]...)
		out = append(out, replacement...)
		out = append(out, doc[loc[1]:]...)
		return out
	}
	return doc
}

// publishAlias copies a leader's completed scan result under an alias
// hostname's own output path, patching the XML's <hostnames> block so the
// report engine attributes the (identical, genuinely shared) result to
// alias instead of leader. The .oN transcript is duplicated best-effort
// with an explanatory header; nothing parses it, so a copy failure there
// is not reported as an error.
func publishAlias(leaderXML, aliasXML, leaderTxt, aliasTxt, leader, alias string) error {
	doc, err := os.ReadFile(leaderXML)
	if err != nil {
		return fmt.Errorf("failed to read shared scan result for %q: %w", leader, err)
	}
	if err := os.WriteFile(aliasXML, rewriteHostnameXML(doc, alias), 0644); err != nil {
		return fmt.Errorf("failed to write scan result for alias host %q: %w", alias, err)
	}
	if txt, err := os.ReadFile(leaderTxt); err == nil {
		header := []byte(fmt.Sprintf(
			"# %s resolves to the same backend as %s; nmap scanned it once and this\n# file is a copy of that result published under %s.\n\n",
			alias, leader, alias,
		))
		_ = os.WriteFile(aliasTxt, append(header, txt...), 0644)
	}
	return nil
}
