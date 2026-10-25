//go:build !linux

package campaign

import "errors"

func nativeProcessPlatform() error {
	return errors.New("release campaign requires native Linux AMD64 execution")
}
func readProcessState(int) (byte, string, error) { return 0, "", nativeProcessPlatform() }
