// direct-fixture-calibration owns one fixed broker-only lifecycle, never a test
// or released-product child, arbitrary command, builder or publisher.
package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/pagrus7/kaferry-lab/internal/campaign"
)

func main() { os.Exit(execute(os.Args[1:])) }

func execute(args []string) int {
	var p campaign.DirectFixtureCalibrationPlan
	flags := flag.NewFlagSet("direct-fixture-calibration", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&p.Repository, "repository", "", "fixed canonical source-only repository")
	flags.StringVar(&p.RunID, "run-id", "", "fresh direct fixture identity")
	flags.StringVar(&p.ReviewedHead, "reviewed-head", "", "reviewed clean source commit")
	flags.StringVar(&p.InputSHA256, "input-sha256", "", "externally bound fixed input")
	if flags.Parse(args) != nil || flags.NArg() != 0 || p.Repository == "" || p.RunID == "" || p.ReviewedHead == "" || p.InputSHA256 == "" {
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if _, err := campaign.RunDirectFixtureCalibration(ctx, p); err != nil {
		return 1
	}
	return 0 // external parent Wait and Mac readback are still required
}
