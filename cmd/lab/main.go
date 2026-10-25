// lab verifies published artifacts, checks offline evidence and calibrates its
// own controllers. Qualification is unavailable until required scenarios exist.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/calibration"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
)

func main() { os.Exit(execute(os.Args[1:])) }
func execute(args []string) int {
	if len(args) == 5 && args[0] == "_standin" {
		if e := calibration.Standin(args[1], args[2], args[3], args[4], os.Stdin, os.Stdout); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		return 0
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: lab verify OUT_DIR | check BUNDLE | calibrate NEW_OUT_DIR | scenario RUN_ID CASE ROUTING NEW_OUT_DIR | qualify")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	budget := 3 * time.Minute
	if args[0] == "scenario" {
		budget = 10 * time.Minute
	}
	ctx, bound := context.WithTimeout(ctx, budget)
	defer bound()
	switch args[0] {
	case "verify":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: lab verify NEW_OUT_DIR (reviewed v0.6.0 linux-amd64 only)")
			return 2
		}
		result, e := verify(ctx, args[1])
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		return output(result)
	case "check":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: lab check BUNDLE")
			return 2
		}
		r := evidence.LoadAndCheck(args[1])
		if output(r) != 0 {
			return 2
		}
		return verdictStatus(r.Verdict)
	case "scenario":
		return runScenario(ctx, args[1:])
	case "calibrate":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: lab calibrate NEW_OUT_DIR")
			return 2
		}
		exe, e := os.Executable()
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		results, e := calibration.Run(ctx, args[1], exe)
		if e != nil {
			_ = output(results)
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		return output(results)
	case "qualify":
		_ = output(map[string]any{"verdict": "UNSUPPORTED", "release_qualified": false, "reason": "required M2-M6 scenario implementation and campaign evidence are incomplete"})
		return 3
	default:
		fmt.Fprintln(os.Stderr, "unknown command", args[0])
		return 2
	}
}
func output(value any) int {
	if e := json.NewEncoder(os.Stdout).Encode(value); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	return 0
}
