package ascii

import (
	_ "embed"
	"fmt"
	"math"
	"strings"
)

// The reference is encoded as palette indices, keeping the terminal asset
// independent of image libraries, font rendering and external files at runtime.
//
//go:embed smith.txt
var smithPixels string

var smithPalette = []struct {
	rgb  string
	ansi int
}{
	{"000000", 0}, {"25212b", 235}, {"46414e", 238}, {"77717e", 243},
	{"b2a9b3", 249}, {"eee2c5", 230}, {"6a3527", 52}, {"a65b37", 130},
	{"e69460", 173}, {"ffd29b", 223}, {"a52327", 124}, {"ed4935", 203},
	{"ed921e", 208}, {"ffe14f", 227},
}

func smithCanvas(tick int) [][]byte {
	rows := strings.Split(strings.TrimSpace(smithPixels), "\n")
	canvas := make([][]byte, len(rows))
	for y, row := range rows {
		canvas[y] = []byte(row)
	}
	phase := ((tick % 8) + 8) % 8
	// Only the raised arm and hammer move. Body, tongs and anvil stay planted.
	angles := []float64{0, 0, 45, 100, 130, 130, 45, 0}
	angle := angles[phase] * math.Pi / 180
	if angle != 0 {
		for y := 0; y < 14; y++ {
			for x := 0; x < 19; x++ {
				canvas[y][x] = '0'
			}
		}
		// Inverse sampling avoids holes when rotating the coarse pixel silhouette.
		for y := 0; y < 36; y++ {
			for x := 0; x < 40; x++ {
				dx, dy := float64(x)-9, float64(y)-15
				sx := int(math.Round(9 + dx*math.Cos(angle) + dy*math.Sin(angle)))
				sy := int(math.Round(15 - dx*math.Sin(angle) + dy*math.Cos(angle)))
				if sx >= 0 && sx < 19 && sy >= 0 && sy < 14 && rows[sy][sx] != '0' {
					canvas[y][x] = rows[sy][sx]
				}
			}
		}
	}
	// Embers above the billet pulse on impact.
	if phase == 4 || phase == 5 {
		for _, p := range [][2]int{{22, 30}, {25, 28}, {28, 31}, {20, 32}} {
			canvas[p[1]][p[0]] = 'd'
		}
	}
	return canvas
}

// ForgeFrame returns a monochrome silhouette with the same dimensions as
// the colored sprite. Compact loading frames use 24 columns / 14 rows.
func ForgeFrame(tick int) string { return renderSmith(tick, 24, 28, false, false) }

// ColoredForgeFrame renders the loading sprite with a truecolor or ANSI-256
// palette. Background pixels use the terminal default, including light themes.
func ColoredForgeFrame(tick int, truecolor bool) string {
	return renderSmith(tick, 24, 28, true, truecolor)
}

func renderSmith(tick, width, height int, colors, truecolor bool) string {
	canvas := smithCanvas(tick)
	index := func(x, y int) int {
		c := canvas[y*48/height][x*40/width]
		return strings.IndexByte("0123456789abcd", c)
	}
	var out strings.Builder
	paint := func(i int, bg bool) string {
		if i == 0 {
			if bg {
				return "\x1b[49m"
			}
			return "\x1b[39m"
		}
		prefix := 38
		if bg {
			prefix = 48
		}
		c := smithPalette[i]
		if !truecolor {
			return fmt.Sprintf("\x1b[%d;5;%dm", prefix, c.ansi)
		}
		var r, g, b int
		_, _ = fmt.Sscanf(c.rgb, "%02x%02x%02x", &r, &g, &b)
		return fmt.Sprintf("\x1b[%d;2;%d;%d;%dm", prefix, r, g, b)
	}
	for y := 0; y < height; y += 2 {
		for x := 0; x < width; x++ {
			top, bottom := index(x, y), index(x, y+1)
			if colors {
				switch {
				case top == 0 && bottom == 0:
					out.WriteString("\x1b[0m ")
				case top == 0:
					out.WriteString(paint(bottom, false) + "\x1b[49m▄")
				case bottom == 0:
					out.WriteString(paint(top, false) + "\x1b[49m▀")
				default:
					out.WriteString(paint(top, false) + paint(bottom, true) + "▀")
				}
			} else {
				switch {
				case top != 0 && bottom != 0:
					out.WriteRune('█')
				case top != 0:
					out.WriteRune('▀')
				case bottom != 0:
					out.WriteRune('▄')
				default:
					out.WriteByte(' ')
				}
			}
		}
		if colors {
			out.WriteString("\x1b[0m")
		}
		if y+2 < height {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// BannerSmith is the larger reference sprite used in the startup composition.
func BannerSmith(colors, truecolor bool) string { return renderSmith(0, 40, 48, colors, truecolor) }

// pixelWordmark uses a five-row bitmap alphabet instead of outline lettering.
func pixelWordmark() string {
	glyphs := map[rune][5]string{
		'S': {"1111", "1000", "1111", "0001", "1111"},
		'C': {"1111", "1000", "1000", "1000", "1111"},
		'A': {"0110", "1001", "1111", "1001", "1001"},
		'N': {"1001", "1101", "1011", "1001", "1001"},
		'F': {"1111", "1000", "1110", "1000", "1000"},
		'O': {"0110", "1001", "1001", "1001", "0110"},
		'R': {"1110", "1001", "1110", "1010", "1001"},
		'G': {"1111", "1000", "1011", "1001", "1111"},
		'E': {"1111", "1000", "1110", "1000", "1111"},
	}
	var rows []string
	for y := 0; y < 5; y++ {
		var row strings.Builder
		for _, letter := range "SCANFORGE" {
			for _, pixel := range glyphs[letter][y] {
				if pixel == '1' {
					row.WriteRune('█')
				} else {
					row.WriteByte(' ')
				}
			}
			row.WriteByte(' ')
		}
		rows = append(rows, strings.TrimRight(row.String(), " "))
	}
	return strings.Join(rows, "\n")
}
