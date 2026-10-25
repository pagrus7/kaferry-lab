//go:build !linux

package campaign

import (
	"errors"
	"os"
)

func nativeProcessPlatform() error {
	return errors.New("release campaign requires native Linux AMD64 execution")
}
func readProcessState(int) (byte, string, error) { return 0, "", nativeProcessPlatform() }

func processUsageFromState(*os.ProcessState) processResourceUsage {
	return processResourceUsage{Source: "os.ProcessState.SysUsage", Error: "wait resource measurements require native Linux accounting; other-platform RSS units are not interpreted"}
}
