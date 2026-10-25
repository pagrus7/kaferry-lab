// link-calibration owns synthetic stock-link controls; it builds, seals and publishes nothing.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/campaign"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--owned-link-group-anchor" {
		// This child opens no files/sockets and produces no output. Parent holds it
		// unreaped through the last group signal. Finite even if signaling is denied.
		time.Sleep(145 * time.Second)
		return
	}
	var p campaign.LinkCalibrationPlan
	var builtAfter string
	flags := flag.NewFlagSet("link-calibration", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // flag errors may contain unreviewed caller bytes
	flags.StringVar(&p.Repository, "repository", "", "absolute current repository root")
	flags.StringVar(&p.RunID, "run-id", "", "fresh owned fixture run")
	flags.StringVar(&p.TestBinary, "test-binary", "", "fresh native campaign test executable")
	flags.StringVar(&p.TestSHA256, "test-sha256", "", "exact test executable SHA-256")
	flags.StringVar(&p.ReviewedHead, "reviewed-head", "", "reviewed clean source commit")
	flags.StringVar(&builtAfter, "built-after", "", "UTC RFC3339Nano build-start timestamp")
	parseErr := flags.Parse(os.Args[1:])
	var err error
	p.BuiltAfter, err = time.Parse(time.RFC3339Nano, builtAfter)
	if parseErr != nil || err != nil || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "link calibration rejected: explicit reviewed build identity required")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Selected facts are in the fixed final receipt. Do no new diagnostic I/O
	// after its terminal private-sink close/marker boundary.
	_, err = campaign.RunLinkCalibration(ctx, p)
	if err != nil {
		os.Exit(1)
	}
}
