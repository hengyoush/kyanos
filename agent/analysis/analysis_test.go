package analysis_test

import (
	"fmt"
	"testing"
)

func TestSlice(t *testing.T) {
	a := make([]int, 8, 8)
	a[2] = 3
	fmt.Println(a)
}
