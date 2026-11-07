// Command gethisengine finds browser profiles and extracts saved passwords,
// history, cookies, bookmarks and autofill data from Chromium- and
// Firefox-based browsers.
package main

import (
	"os"

	"gethisengine/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
