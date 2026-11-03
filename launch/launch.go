// Package launch runs the urfluency command line. cmd/urfluency is the
// community build; another module can build the CLI with more analyzers or
// extensions registered, by importing them and calling Main.
package launch

import (
	"context"
	"os"
	"os/signal"

	"github.com/rburns629/urfluency-cli/internal/cli"
)

// Main runs urfluency with the process's arguments and exits.
func Main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
