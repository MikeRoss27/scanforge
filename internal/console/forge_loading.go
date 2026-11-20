package console

import (
	"bytes"
	_ "embed"
	"fmt"
	imgcolor "image/color"
	"image/png"
	"math"
	"strings"
	"time"
)

//go:embed assets/forge-loading-v2.png
var forgeSheet []byte

const forgeWidth = 16
const forgeHeight = 12
const forgeRows = forgeHeight / 2

// Palette zero is transparent. Steel, wood and embers remain distinct even
// without truecolor. Sampling happens once, never on the renderer's ticker.
var forgePalette = []struct{ r, g, b, ansi int }{
	{0, 0, 0, 0}, {48, 46, 57, 236}, {88, 89, 106, 240}, {168, 178, 195, 249},
	{227, 235, 240, 255}, {158, 96, 43, 130}, {255, 145, 0, 208}, {255, 213, 41, 220},
}
var forgePixels = loadForgePixels()

// 30fps reads as noticeably livelier than the old 25fps tick, and keeps the
// strike-to-strike cycle under a second instead of 1.6s.
const forgeAnimationInterval = 33 * time.Millisecond
const forgeCycleFrames = 40

// Animate one rigid hammer sampled from imagegen's first pose. Using a
// canonical shape avoids the scale/handle changes between generated poses.
func loadForgePixels() [forgeCycleFrames][forgeHeight][forgeWidth]int {
	var frames [forgeCycleFrames][forgeHeight][forgeWidth]int
	sheet, err := png.Decode(bytes.NewReader(forgeSheet))
	if err != nil {
		panic("invalid embedded forge loading sheet: " + err.Error())
	}
	bounds := sheet.Bounds()
	w, h := float64(bounds.Dx())/4, float64(bounds.Dy())/2
	sample := func(x, y float64) imgcolor.NRGBA {
		if x < 0 || y < 0 || x >= w || y >= h {
			return imgcolor.NRGBA{}
		}
		return imgcolor.NRGBAModel.Convert(sheet.At(bounds.Min.X+int(x), bounds.Min.Y+int(y))).(imgcolor.NRGBA)
	}
	// The handle's low end is the fixed pivot; the head falls onto the billet.
	px, py := w*.27, h*.44
	for frame := range frames {
		angle := forgeHammerAngle(frame) * math.Pi / 180
		cosine, sine := math.Cos(angle), math.Sin(angle)
		for y := 0; y < forgeHeight; y++ {
			for x := 0; x < forgeWidth; x++ {
				var bestColor imgcolor.NRGBA
				var coverage, brightest int
				for sy := 0; sy < 4; sy++ {
					for sx := 0; sx < 4; sx++ {
						dx := (float64(x) + (float64(sx)+.5)/4) * w / forgeWidth
						dy := (float64(y) + (float64(sy)+.5)/4) * h / forgeHeight
						var pixel imgcolor.NRGBA
						// The entire anvil, including its glowing billet, stays identical.
						if dy >= h*.54 {
							pixel = sample(dx, dy)
						}
						hx := px + (dx-px)*cosine + (dy-py)*sine
						hy := py - (dx-px)*sine + (dy-py)*cosine
						if hy < h*.54 {
							hammer := sample(hx, hy)
							if hammer.A >= 128 {
								pixel = hammer
							}
						}
						if pixel.A < 128 {
							continue
						}
						coverage++
						light := int(pixel.R)*3 + int(pixel.G)*6 + int(pixel.B)
						if light > brightest {
							bestColor, brightest = pixel, light
						}
					}
				}
				if coverage < 4 {
					continue
				}
				best, distance := 1, int(^uint(0)>>1)
				for i, c := range forgePalette[1:] {
					r, g, b := int(bestColor.R)-c.r, int(bestColor.G)-c.g, int(bestColor.B)-c.b
					d := r*r + g*g + b*b
					if d < distance {
						best, distance = i+1, d
					}
				}
				frames[frame][y][x] = best
			}
		}
		// Sparks exist only just after impact, and move away from the billet.
		if frame >= 11 && frame <= 16 {
			age := frame - 11
			for _, p := range [][2]int{{8 - age/2, 6 - age/2}, {11 + age/2, 6 - age/3}} {
				if p[0] >= 0 && p[0] < forgeWidth && p[1] >= 0 {
					frames[frame][p[1]][p[0]] = 7
				}
			}
		}
		// Lock the lower anvil silhouette after compositing the moving layer.
		if frame > 0 {
			for y := 8; y < forgeHeight; y++ {
				frames[frame][y] = frames[0][y]
			}
		}
	}
	return frames
}

func forgeHammerAngle(frame int) float64 {
	switch {
	case frame == 0:
		return 0 // loop seam: must match the last frame exactly
	case frame < 6:
		// A faint breathing sway instead of a dead hold: the hammer never
		// sits frozen while it gathers for the strike. Returns to exactly 0
		// by frame 5 so it joins the downswing without a jump.
		t := float64(frame) / 5
		return -2 * math.Sin(t*math.Pi)
	case frame <= 11:
		t := float64(frame-6) / 5
		return 50 * t * t // accelerate into contact
	case frame <= 15:
		t := float64(frame-11) / 4
		return 50 - 13*(1-(1-t)*(1-t)) // quick recoil, slowing at the top
	case frame < 36:
		t := float64(frame-15) / 21
		return 37 * (1 - t*t*(3-2*t)) // ease back to the raised pose
	case frame >= forgeCycleFrames-1:
		return 0 // loop seam: must match the first frame exactly
	default:
		// Same faint sway on the way down to the rest pose, landing back on
		// exactly 0 at the last frame so the loop seam is invisible.
		t := float64(frame-36) / 3
		return -2 * math.Sin(t*math.Pi)
	}
}

func forgeFrameIndex(now time.Time) int {
	tick := now.UnixNano() / int64(forgeAnimationInterval)
	return int((tick%forgeCycleFrames + forgeCycleFrames) % forgeCycleFrames)
}

func forgeLoadingRows(now time.Time, th theme) []string {
	pixels := forgePixels[forgeFrameIndex(now)]
	paint := func(index int, background bool) string {
		prefix := 38
		if background {
			prefix = 48
		}
		if index == 0 {
			if background {
				return "\x1b[49m"
			}
			return "\x1b[39m"
		}
		c := forgePalette[index]
		if th.truecolor {
			return fmt.Sprintf("\x1b[%d;2;%d;%d;%dm", prefix, c.r, c.g, c.b)
		}
		return fmt.Sprintf("\x1b[%d;5;%dm", prefix, c.ansi)
	}
	rows := make([]string, 0, forgeRows)
	for y := 0; y < forgeHeight; y += 2 {
		var row strings.Builder
		for x := 0; x < forgeWidth; x++ {
			top, bottom := pixels[y][x], pixels[y+1][x]
			if !th.enabled {
				switch {
				case top == 0 && bottom == 0:
					row.WriteByte(' ')
				case top == 0:
					row.WriteRune('▄')
				case bottom == 0:
					row.WriteRune('▀')
				default:
					row.WriteRune('█')
				}
				continue
			}
			switch {
			case top == 0 && bottom == 0:
				row.WriteString("\x1b[0m ")
			case top == 0:
				row.WriteString(paint(bottom, false) + "\x1b[49m▄")
			case bottom == 0:
				row.WriteString(paint(top, false) + "\x1b[49m▀")
			default:
				row.WriteString(paint(top, false) + paint(bottom, true) + "▀")
			}
		}
		if th.enabled {
			row.WriteString("\x1b[0m")
		}
		rows = append(rows, row.String())
	}
	return rows
}
