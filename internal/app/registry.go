package app

import (
	"github.com/MikeRoss27/scanforge/internal/config"
	"github.com/MikeRoss27/scanforge/internal/modules"
	"github.com/MikeRoss27/scanforge/internal/modules/attacksurface"
	"github.com/MikeRoss27/scanforge/internal/modules/dnsbrute"
	"github.com/MikeRoss27/scanforge/internal/modules/dnsx"
	"github.com/MikeRoss27/scanforge/internal/modules/ffuf"
	"github.com/MikeRoss27/scanforge/internal/modules/gau"
	"github.com/MikeRoss27/scanforge/internal/modules/httpcheck"
	"github.com/MikeRoss27/scanforge/internal/modules/httpx"
	"github.com/MikeRoss27/scanforge/internal/modules/jssecrets"
	"github.com/MikeRoss27/scanforge/internal/modules/jsverify"
	"github.com/MikeRoss27/scanforge/internal/modules/katana"
	"github.com/MikeRoss27/scanforge/internal/modules/naabu"
	"github.com/MikeRoss27/scanforge/internal/modules/nmap"
	"github.com/MikeRoss27/scanforge/internal/modules/nuclei"
	"github.com/MikeRoss27/scanforge/internal/modules/payloadgen"
	"github.com/MikeRoss27/scanforge/internal/modules/screenshot"
	"github.com/MikeRoss27/scanforge/internal/modules/subfinder"
	"github.com/MikeRoss27/scanforge/internal/modules/techcve"
	"github.com/MikeRoss27/scanforge/internal/modules/tlsx"
	"github.com/MikeRoss27/scanforge/internal/modules/wafw00f"
	"github.com/MikeRoss27/scanforge/internal/modules/whatweb"
)

// buildRegistry wires every scanner integration into a registry, resolving
// tool paths from the config. New modules are registered here.
func buildRegistry(cfg *config.Config) *modules.Registry {
	registry := modules.NewRegistry()
	registry.Register(subfinder.New(cfg.ToolPath("subfinder")))
	registry.Register(dnsbrute.New(cfg.ToolPath("shuffledns")))
	registry.Register(dnsx.New(cfg.ToolPath("dnsx")))
	registry.Register(httpx.New(cfg.ToolPath("httpx")))
	registry.Register(naabu.New(cfg.ToolPath("naabu")))
	registry.Register(nmap.New(cfg.ToolPath("nmap")))
	registry.Register(whatweb.New(cfg.ToolPath("whatweb")))
	registry.Register(wafw00f.New(cfg.ToolPath("wafw00f")))
	registry.Register(katana.New(cfg.ToolPath("katana")))
	registry.Register(jssecrets.New())
	registry.Register(jsverify.New(cfg.ToolPath("chromium")))
	registry.Register(attacksurface.New())
	registry.Register(ffuf.New(cfg.ToolPath("ffuf")))
	registry.Register(nuclei.New(cfg.ToolPath("nuclei")))
	registry.Register(gau.New(cfg.ToolPath("gau")))
	registry.Register(tlsx.New(cfg.ToolPath("tlsx")))
	registry.Register(techcve.New())
	registry.Register(httpcheck.New())
	registry.Register(payloadgen.New())
	registry.Register(screenshot.New(cfg.ToolPath("httpx")))
	return registry
}
