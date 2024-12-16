package common

import (
	"os"
	"strings"
)

func Is256ColorSupported() bool {
	term := os.Getenv("TERM")
	return strings.Contains(term, "256color")
}
