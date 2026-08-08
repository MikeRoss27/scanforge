// Package ascii renders the ScanForge ASCII banner shown at startup.
package ascii

import (
	"fmt"
	"strings"

	"github.com/MikeRoss27/scanforge/internal/ui"
)

// Bannières disponibles
const (
	// Style 1 : Blocs Unicode gras (issu de ascii.txt)
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

	// Style 2 : Classic Slant très lisible
	BannerClassic = `
   _____                 ______                       
  / ___/_________ _____ / ____/___  _________ ____  
  \__ \/ ___/ __ '/ __ \/ /_  / __ \/ ___/ __ '/ _ \ 
 ___/ / /__/ /_/ / / / / __/ / /_/ / /  / /_/ /  __/ 
/____/\___/\__,_/_/ /_/_/    \____/_/   \__, /\___/  
                                       /____/       `

	// Style 3 : 3D Ombré (issu de ascii.txt)
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

// PrintBanner affiche la bannière "Blocks" avec un dégradé cyan → magenta
// constant, pour une identité visuelle cohérente à chaque exécution (le choix
// aléatoire de bannière et de dégradé rendait la marque instable d'un run à
// l'autre).
func PrintBanner() {
	for _, line := range strings.Split(BannerBlocks, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fmt.Println(ui.Gradient(line, ui.AccentCyan, ui.AccentMagenta))
	}
	fmt.Println()
}
