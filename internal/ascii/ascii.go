// Package ascii renders the ScanForge ASCII banner shown at startup.
package ascii

import (
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/ui"
)

// Available banners
const (
	// Style 1: bold Unicode blocks (from ascii.txt)
	BannerBlocks = `
   ▄████████  ▄████████    ▄████████ ███▄▄▄▄      ▄████████  ▄██████▄     ▄████████    ▄██████▄     ▄████████
  ███    ███ ███    ███   ███    ███ ███▀▀▀██▄   ███    ███ ███    ███   ███    ███   ███    ███   ███    ███
  ███    █▀  ███    █▀    ███    ███ ███   ███   ███    █▀  ███    ███   ███    ███   ███    █▀    ███    █▀
  ███        ███          ███    ███ ███   ███  ▄███▄▄▄     ███    ███  ▄███▄▄▄▄██▀  ▄███         ▄███▄▄▄
▀███████████ ███        ▀███████████ ███   ███ ▀▀███▀▀▀     ███    ███ ▀▀███▀▀▀▀▀   ▀▀███ ████▄  ▀▀███▀▀▀
         ███ ███    █▄    ███    ███ ███   ███   ███        ███    ███ ▀███████████   ███    ███   ███    █▄
   ▄█    ███ ███    ███   ███    ███ ███   ███   ███        ███    ███   ███    ███   ███    ███   ███    ███
 ▄████████▀  ████████▀    ███    █▀   ▀█   █▀    ███         ▀██████▀    ███    ███   ████████▀    ██████████
                                                                          ███    ███`

	// Style 2: classic slant, very readable
	BannerClassic = `
   _____                 ______                       
  / ___/_________ _____ / ____/___  _________ ____  
  \__ \/ ___/ __ '/ __ \/ /_  / __ \/ ___/ __ '/ _ \ 
 ___/ / /__/ /_/ / / / / __/ / /_/ / /  / /_/ /  __/ 
/____/\___/\__,_/_/ /_/_/    \____/_/   \__, /\___/  
                                       /____/       `

	// Style 3: 3D shaded (from ascii.txt)
	BannerSlanted = `
  ______    ______    ______   __    __  ________  ______   _______    ______   ________
 /      \  /      \  /      \ /  \  /  |/        |/      \ /       \  /      \ /        |
/$$$$$$  |/$$$$$$  |/$$$$$$  |$$  \ $$ |$$$$$$$$//$$$$$$  |$$$$$$$  |/$$$$$$  |$$$$$$$$/
$$ \__$$/ $$ |  $$/ $$ |__$$ |$$$  \$$ |$$ |__   $$ |  $$ |$$ |__$$ |$$ | _$$/ $$ |__
$$      \ $$ |      $$    $$ |$$$$  $$ |$$    |  $$ |  $$ |$$    $$< $$ |/    |$$    |
 $$$$$$  |$$ |   __ $$$$$$$$ |$$ $$ $$ |$$$$$/   $$ |  $$ |$$$$$$$  |$$ |$$$$ |$$$$$/
/  \__$$ |$$ \__/  |$$ |  $$ |$$ |$$$$ |$$ |     $$ \__$$ |$$ |  $$ |$$ \__$$ |$$ |_____
$$    $$/ $$    $$/ $$ |  $$ |$$ | $$$ |$$ |     $$    $$/ $$ |  $$ |$$    $$/ $$       |
 $$$$$$/   $$$$$$/  $$/   $$/ $$/   $$/ $$/       $$$$$$/  $$/   $$/  $$$$$$/  $$$$$$$$/`
)

// PrintBanner prints the "Blocks" banner with a constant cyan → magenta
// gradient, for a consistent visual identity on every run (random banner and
// gradient selection made the branding unstable from one run to the next).
func PrintBanner() {
	for _, line := range strings.Split(BannerBlocks, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fmt.Println(ui.Gradient(line, ui.AccentCyan, ui.AccentMagenta))
	}
	fmt.Println()
}
