package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/campaign"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

func runScenario(ctx context.Context, args []string) int {
	if len(args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: lab scenario RUN_ID CASE PRESERVE|KEY NEW_OUT_DIR")
		return 2
	}
	id, scenario, routing, directory := args[0], args[1], args[2], args[3]
	switch scenario {
	case "healthy", "repeated-kill", "delivery-stop", "delivery-threshold", "source-startup", "source-save":
	default:
		fmt.Fprintln(os.Stderr, "unsupported M2 scenario")
		return 3
	}
	if routing != "PRESERVE" && routing != "KEY" {
		fmt.Fprintln(os.Stderr, "scenario routing must be PRESERVE or KEY")
		return 2
	}
	state, err := fixture.Load(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	directory, err = filepath.Abs(directory)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(directory), 0700)
	}
	if err == nil {
		err = os.Mkdir(directory, 0700)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	source, err := scenarioBuildSource()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// Every scenario verifies the published archive, provenance and native
	// version afresh. No caller-supplied executable or cached claim is admitted.
	verified, err := verify(ctx, filepath.Join(directory, "release"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	report, runErr := campaign.RunM2Scenario(ctx, campaign.ScenarioPlan{
		ID: scenario, Routing: routing, Directory: directory,
		Executable: filepath.Join(verified.Directory, "kaferry"),
		Subject:    verified.artifactEvidence.Subject, Artifact: verified.artifactEvidence,
		LabSource: source,
		Records:   96, Budget: 5 * time.Minute,
		WireToolReceipt: os.Getenv("KAFERRY_LAB_WIRE_RECEIPT"),
	}, state, fixture.Docker)
	result := evidence.LoadAndCheck(filepath.Join(directory, "bundle"))
	if output(struct {
		Report campaign.ScenarioReport `json:"report"`
		Result evidence.Result         `json:"result"`
	}{report, result}) != 0 {
		return 2
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, runErr)
		return 2
	}
	return verdictStatus(result.Verdict)
}

func verdictStatus(verdict evidence.Verdict) int {
	switch verdict {
	case evidence.Pass:
		return 0
	case evidence.Violation:
		return 1
	case evidence.Unsupported:
		return 3
	case evidence.Inconclusive:
		return 4
	default:
		return 2
	}
}

func scenarioBuildSource() (evidence.LabSource, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return evidence.LabSource{}, fmt.Errorf("scenario requires recorded Go VCS build information")
	}
	var source evidence.LabSource
	var vcs, modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs":
			vcs = setting.Value
		case "vcs.revision":
			source.Commit = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	dirty, err := strconv.ParseBool(modified)
	if err != nil || vcs != "git" || len(source.Commit) != 40 || dirty {
		return evidence.LabSource{}, fmt.Errorf("scenario requires a clean recorded Git source build")
	}
	source.Dirty = dirty
	source.Proof = "Go build information: vcs=git; vcs.revision=" + source.Commit + "; vcs.modified=" + modified + "; " + info.GoVersion
	return source, nil
}
