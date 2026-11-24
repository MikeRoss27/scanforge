package mcp

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func obj(required []string, props map[string]any) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

var runIDProp = str("Run id as returned by list_runs: <target-dir>/<timestamp>")

func toolDefs() []toolDef {
	ro := map[string]any{"readOnlyHint": true}
	active := map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true}
	return []toolDef{
		{"scanforge.list_runs", "List runs from the local run store, newest first.",
			obj(nil, map[string]any{"target": str("Substring filter on target"), "limit": num("Max runs (default 100)")}), ro},
		{"scanforge.get_run", "Get one run: status, modules, scope provenance, counts.",
			obj([]string{"run_id"}, map[string]any{"run_id": runIDProp}), ro},
		{"scanforge.get_assets", "Get the assets (hosts, ports, HTTP, TLS, technologies) of a run.",
			obj([]string{"run_id"}, map[string]any{"run_id": runIDProp, "filter": str("Substring filter on asset name"), "limit": num("Page size (default 200, max 1000)"), "offset": num("Page offset")}), ro},
		{"scanforge.get_findings", "Get findings of a run, most severe first. Each finding carries provenance, status (potential|version-match|validated|inconclusive), confidence and evidence_items (kind, summary, artifact, excerpt, verified_by): only treat a finding as proven when status is validated. Leaked secret values are returned unmasked as found on the target.",
			obj([]string{"run_id"}, map[string]any{"run_id": runIDProp, "severity": str("critical|high|medium|low|info"), "asset": str("Substring filter on asset"), "source": str("Producer, e.g. nuclei, jssecrets"), "kind": str("vulnerability|verified_secret"), "status": str("potential|version-match|validated|inconclusive"), "confidence": str("low|medium|high"), "limit": num("Page size"), "offset": num("Page offset")}), ro},
		{"scanforge.get_evidence", "Get evidence: for a finding_id, or a raw artifact file under 01_..06_ (slice with offset/max_bytes), or the list of evidence files when neither is given.",
			obj([]string{"run_id"}, map[string]any{"run_id": runIDProp, "finding_id": str("Finding id (F-...)"), "file": str("Relative artifact path, e.g. 06_vulns/js-secrets.jsonl"), "offset": num("Byte offset"), "max_bytes": num("Max bytes (default 262144, max 1048576)")}), ro},
		{"scanforge.plan_scan", "Validate a profile/scope and return the execution waves. Runs nothing and creates no run directory.",
			obj([]string{"target"}, map[string]any{"target": str("Target host, URL or IP"), "profile": str("Profile name (default from config)"), "wp": boolean("Add the WordPress chain")}), ro},
		{"scanforge.start_authorized_scan", "DISABLED unless the operator enabled --allow-active with an explicit --scope file. Starts a scan of a target that is in that scope file.",
			obj([]string{"target"}, map[string]any{"target": str("Target; must be allowed by the server scope file"), "profile": str("Profile name (default safe)"), "dry_run": boolean("Record commands without network access")}), active},
		{"scanforge.stop_scan", "DISABLED unless --allow-active. Gracefully stops a scan started by this server.",
			obj([]string{"scan_id"}, map[string]any{"scan_id": str("scan_id returned by start_authorized_scan")}), active},
	}
}

func knownTool(name string) bool {
	for _, t := range toolDefs() {
		if t.Name == name {
			return true
		}
	}
	return false
}
