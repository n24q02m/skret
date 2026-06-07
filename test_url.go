package main

import (
    "fmt"
    "net/url"
)

func main() {
    u, err := url.Parse("http://bad-url\x7f")
    fmt.Println(u, err)

    joined, err := url.JoinPath("http://bad-url\x7f", "path")
    fmt.Println(joined, err)
}
