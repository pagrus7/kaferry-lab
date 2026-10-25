// fixture starts/stops owned Kafka fixtures with optional standard worker links.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func execute() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: fixture up|up-links|down|env RUN_ID")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	action, id := os.Args[1], os.Args[2]
	var s fixture.State
	var err error
	switch action {
	case "up":
		s, err = fixture.Up(ctx, id, fixture.Docker)
	case "up-links":
		s, err = fixture.UpLinks(ctx, id, fixture.Docker)
	case "down":
		s, err = fixture.Load(id)
		if err == nil {
			err = fixture.Down(ctx, s, fixture.Docker)
		}
	case "env":
		s, err = fixture.Load(id)
		if err == nil {
			fmt.Printf("export LAB_RUN_ID=%q\nexport LAB_SOURCE_ADDR=%q\nexport LAB_DEST_ADDR=%q\n", s.RunID, s.Source, s.Destination)
			if s.Proxy != nil {
				fmt.Printf("export LAB_WORKER_SOURCE_ADDR=%q\nexport LAB_WORKER_DEST_ADDR=%q\nexport LAB_PROXY_API_ADDR=%q\n", s.WorkerSource, s.WorkerDestination, s.Proxy.API)
			}
			return nil
		}
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(s)
}
