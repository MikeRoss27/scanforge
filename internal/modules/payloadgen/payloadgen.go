// Package payloadgen derives contextual fuzzing payloads from the scan's
// own findings: API endpoints discovered in JavaScript, parameters harvested
// from historical URLs, and technology-specific endpoints. The generated
// wordlists are published as artifacts for reuse in ffuf, nuclei custom
// templates or manual testing.
package payloadgen

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/runner"
	"golang.org/x/sync/errgroup"
)

const (
	outputDir = "04_payloads"

	fileAPIPaths      = "api-paths.txt"
	fileAPIEndpoints  = "api-endpoints.txt"
	fileParameters    = "parameters.txt"
	fileTechEndpoints = "tech-endpoints.txt"
	fileManifest      = "manifest.jsonl"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "payloadgen" }
func (m *Module) Description() string {
	return "Generates contextual wordlists (API paths, parameters, tech endpoints) from scan findings"
}
func (m *Module) Requires() []string { return []string{"alive_urls"} }
func (m *Module) Produces() []string { return []string{"payload_wordlists"} }

func (m *Module) Run(ctx context.Context, runCtx *modules.RunContext, _ runner.Executor) (*modules.Result, error) {
	// Fast path: context already cancelled.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var (
		mu           sync.Mutex
		apiPaths     []string
		apiEndpoints []string
		parameters   []string
		techs        []string
		registry     = getTechRegistry()
	)

	g, gctx := errgroup.WithContext(ctx)

	if art, ok := runCtx.GetArtifact("js_secrets"); ok {
		art := art
		g.Go(func() error {
			endpoints, err := readJSEndpointsWithContext(gctx, runCtx.Run.Path(art.Path))
			if err != nil {
				return fmt.Errorf("failed to read JS endpoints: %w", err)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, endpoint := range endpoints {
				apiEndpoints = append(apiEndpoints, endpoint)
				if path := endpointPath(endpoint); path != "" {
					apiPaths = append(apiPaths, path)
					apiPaths = append(apiPaths, path+".json")
				}
			}
			return nil
		})
	}

	if art, ok := runCtx.GetArtifact("historical_urls"); ok {
		art := art
		g.Go(func() error {
			params, err := readParametersWithContext(gctx, runCtx.Run.Path(art.Path))
			if err != nil {
				return fmt.Errorf("failed to read historical URLs: %w", err)
			}
			mu.Lock()
			parameters = append(parameters, params...)
			mu.Unlock()
			return nil
		})
	}

	if art, ok := runCtx.GetArtifact("whatweb_raw"); ok {
		art := art
		g.Go(func() error {
			t, err := readTechsWithContext(gctx, runCtx.Run.Path(art.Path))
			// readTechsWithContext internally uses registry, but we also need raw tech names
			// to map to endpoints. readTechs already normalizes.
			if err != nil {
				return fmt.Errorf("failed to read whatweb output: %w", err)
			}
			mu.Lock()
			techs = append(techs, t...)
			mu.Unlock()
			return nil
		})
		_ = registry // used indirectly via readTechs
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Resolve tech -> endpoints using the effective registry (includes user overrides).
	var techPaths []string
	for _, tech := range techs {
		if eps := lookupTechEndpoints(registry, tech); len(eps) > 0 {
			techPaths = append(techPaths, eps...)
		} else if eps, ok := registry[tech]; ok {
			techPaths = append(techPaths, eps...)
		}
	}

	apiPaths = dedupe(apiPaths)
	apiEndpoints = dedupe(apiEndpoints)
	parameters = dedupe(parameters)
	techPaths = dedupe(techPaths)
	sort.Strings(apiPaths)
	sort.Strings(apiEndpoints)
	sort.Strings(parameters)
	sort.Strings(techPaths)

	now := time.Now().UTC().Format(time.RFC3339)
	files := map[string]struct {
		values []string
		source string
	}{
		fileAPIPaths:      {values: apiPaths, source: "js_secrets"},
		fileAPIEndpoints:  {values: apiEndpoints, source: "js_secrets"},
		fileParameters:    {values: parameters, source: "historical_urls"},
		fileTechEndpoints: {values: techPaths, source: "whatweb_raw"},
	}

	var manifest []ManifestEntry
	for name, entry := range files {
		if len(entry.values) == 0 {
			continue
		}
		if err := writeList(runCtx.Run.Path(outputDir, name), entry.values); err != nil {
			return nil, err
		}
		manifest = append(manifest, ManifestEntry{
			Name:        name,
			Path:        outputDir + "/" + name,
			Count:       len(entry.values),
			Source:      entry.source,
			GeneratedAt: now,
		})
	}
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].Name < manifest[j].Name })

	if err := writeManifest(runCtx.Run.Path(outputDir, fileManifest), manifest); err != nil {
		return nil, err
	}

	if err := runner.AppendCommandLog(runCtx.Run.CommandsLog, runner.Command{
		Name: "payloadgen (native)",
		Args: []string{
			"-wordlists", fmt.Sprintf("%d", len(manifest)),
			"-api-paths", fmt.Sprintf("%d", len(apiPaths)),
			"-parameters", fmt.Sprintf("%d", len(parameters)),
			"-tech-endpoints", fmt.Sprintf("%d", len(techPaths)),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to write commands log: %w", err)
	}

	if err := runCtx.AddArtifact("payload_wordlists", modules.Artifact{
		Name: "payload_wordlists",
		Type: "jsonl",
		Path: outputDir + "/" + fileManifest,
	}); err != nil {
		return nil, fmt.Errorf("failed to publish payload wordlists: %w", err)
	}

	return &modules.Result{
		Name:   m.Name(),
		Status: "completed",
		OutputFiles: map[string]string{
			"payload_wordlists":      outputDir + "/" + fileManifest,
			"payload_api_paths":      outputDir + "/" + fileAPIPaths,
			"payload_parameters":     outputDir + "/" + fileParameters,
			"payload_tech_endpoints": outputDir + "/" + fileTechEndpoints,
		},
	}, nil
}
