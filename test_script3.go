package main

import (
	"fmt"
	"strings"
)

func main() {
	fmt.Println(strings.Contains("foo", "$"))
	fmt.Println(strings.IndexByte("foo", '$') >= 0)
}
