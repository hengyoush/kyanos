package common

import (
	"github.com/muesli/termenv"
)

func Is256ColorSupported() bool {
	colorProfile := termenv.DefaultOutput().ColorProfile()
	return colorProfile == termenv.ANSI256 || colorProfile == termenv.TrueColor
}
