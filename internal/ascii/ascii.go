// Package ascii renders the ScanForge ASCII banner shown at startup.
package ascii

import (
	"fmt"
	"math/rand"
	"os"
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

	// Style 4: Skull
	BannerSkull = `
	.                                                      .
        .n                   .                 .                  n.
   .   .dP                  dP                   9b                 9b.    .
  4    qXb         .       dX                     Xb       .        dXp     t
 dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
 9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
  9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
   9XXXXXXXXXXXXXXXXXXXXX'~   ~'OOO8b   d8OOO'~   ~'XXXXXXXXXXXXXXXXXXXXXP'
     9XXXXXXXXXXXP' '9XX'          '98v8P'          'XXP' '9XXXXXXXXXXXP'
         ~~~~~~~       9X.    .db|db.   .   .db|db.    .XP       ~~~~~~~
                           )b.  .dbo.dP''b  dP''bo.db.  .dX(
                         ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                        dXXXXXXXXXXXP'   .   '9XXXXXXXXXXXb
                       dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                       9XXb'   'XXXXXb.dX|Xb.dXXXXX'   'dXXP
                        '      9XXXXXX(   )XXXXXXP      '
                                 XXXX X.' '.X XXXX
                                 XP^X'b   d'X^XX
                                 X. 9  '   '  P )X
                                 'b  '       '  d'
                                  '             '
                                By MikeRoss
`
)

// PrintBanner prints one of the 4 banners. By default it picks randomly
// among Blocks/Classic/Slanted/Skull so l'ascii art change à chaque run.
// Pour figer un style : SCANFORGE_BANNER=blocks|classic|slanted|skull|off
// (ex: SCANFORGE_BANNER=classic ./scanforge run ...). Sans env, random.
// Le rendu reste monochrome bleu calme (ui.Primary) — plus de dégradé
// violet/rose. Historiquement le code tirait au hasard parmi 3 banners avec
// 3 gradients (a18501d), puis a été figé sur Blocks + gradient cyan→magenta
// pour "branding stable" — d'où l'impression que "ça ne change jamais"
// alors que 4 const existent mais une seule était utilisée.
func PrintBanner() {
	style := strings.ToLower(strings.TrimSpace(os.Getenv("SCANFORGE_BANNER")))
	var banner string
	switch style {
	case "blocks":
		banner = BannerBlocks
	case "classic":
		banner = BannerClassic
	case "slanted":
		banner = BannerSlanted
	case "skull":
		banner = BannerSkull
	case "off", "none", "0", "false":
		return
	case "random", "":
		banners := []string{BannerBlocks, BannerClassic, BannerSlanted, BannerSkull}
		banner = banners[rand.Intn(len(banners))]
	default:
		// valeur inconnue -> random par défaut
		banners := []string{BannerBlocks, BannerClassic, BannerSlanted, BannerSkull}
		banner = banners[rand.Intn(len(banners))]
	}

	for _, line := range strings.Split(banner, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fmt.Println(ui.Primary(line))
	}
	fmt.Println()
}

// BannerNames returns the list of valid SCANFORGE_BANNER values.
func BannerNames() []string {
	return []string{"blocks", "classic", "slanted", "skull", "random", "off"}
}
