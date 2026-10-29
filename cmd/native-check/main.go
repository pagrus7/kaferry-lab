// native-check owns one fixed harness unit-check tree, never a product campaign.
package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/campaign"
)

func main() { os.Exit(execute(os.Args[1:])) }

func execute(args []string) int {
	if len(args) == 1 && args[0] == "--owned-native-check-anchor" {
		// No files, output, sockets or children. Finite even if signaling fails.
		time.Sleep(390 * time.Second)
		return 0
	}
	p, err := parse(args)
	if err != nil {
		return 2 // raw caller-controlled arguments never enter the CI console
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if _, err := campaign.RunNativeCheck(ctx, p); err != nil {
		return 1
	}
	return 0
}

func parse(args []string) (p campaign.NativeCheckPlan, err error) {
	flags := flag.NewFlagSet("native-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&p.Repository, "repository", "", "canonical source-only root")
	flags.StringVar(&p.RunID, "run-id", "", "fresh exclusive attempt")
	flags.StringVar(&p.ReviewedHead, "reviewed-head", "", "approved source head")
	flags.StringVar(&p.InputSHA256, "input-sha256", "", "externally bound fixed input")
	err = flags.Parse(args)
	if err == nil && (flags.NArg() != 0 || p.Repository == "" || p.RunID == "" || p.ReviewedHead == "" || p.InputSHA256 == "") {
		err = flag.ErrHelp
	}
	return
}
