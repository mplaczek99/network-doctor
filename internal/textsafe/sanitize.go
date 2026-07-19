// Package textsafe removes terminal control sequences from untrusted text.
// Anything from the network (banners, tool output) passes through Clean
// before hitting the screen, so a hostile server can't redraw our terminal.
package textsafe

import (
	"regexp"
	"strings"
	"unicode"
)

// escapeRe matches CSI (ESC [ ... final), OSC (ESC ] ... BEL|ST), and any
// other two-byte ESC sequence. CSI/OSC listed first — alternation is
// first-match-wins, and the generic 2-byte form would otherwise eat the
// introducer and leave the payload behind as "clean" text.
var escapeRe = regexp.MustCompile(`\x1b\[[0-9:;<=>?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]`)

// Clean strips escape sequences and control runes from external text.
// Tabs become spaces; everything else in the control range (lone ESC, C1,
// even newlines) and invalid UTF-8 gets dropped. Newlines because Clean is
// single-line by contract — streaming callers split first, so a newline
// showing up here is nobody's friend.
func Clean(s string) string {
	// Whole sequences first; the rune filter would strip the ESC and
	// leave "[31m" behind looking innocent.
	s = escapeRe.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r == unicode.ReplacementChar: // invalid UTF-8
			return -1
		case unicode.IsControl(r): // C0 + C1, incl. ESC and \n
			return -1
		default:
			return r
		}
	}, s)
}
