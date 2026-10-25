//go:build linux

package campaign

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func nativeProcessPlatform() error {
	var kernel syscall.Utsname
	if err := syscall.Uname(&kernel); err != nil {
		return err
	}
	var machine strings.Builder
	for _, c := range kernel.Machine {
		if c == 0 {
			break
		}
		machine.WriteByte(byte(c))
	}
	// An AMD64 Go executable on an ARM64 Linux kernel is emulated, not native.
	if runtime.GOARCH != "amd64" || machine.String() != "x86_64" {
		return errors.New("release campaign requires native Linux AMD64 execution")
	}
	return nil
}

func readProcessState(pid int) (byte, string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}
	return parseProcessStat(string(data), pid)
}

func parseProcessStat(stat string, pid int) (byte, string, error) {
	// comm may contain spaces and parentheses, so split at the final ')'.
	close := strings.LastIndexByte(stat, ')')
	open := strings.IndexByte(stat, '(')
	if open < 1 || close <= open || strings.TrimSpace(stat[:open]) != strconv.Itoa(pid) {
		return 0, "", errors.New("invalid owned process stat identity")
	}
	fields := strings.Fields(stat[close+1:])
	if len(fields) < 20 || len(fields[0]) != 1 {
		return 0, "", errors.New("incomplete owned process stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return 0, "", errors.New("invalid owned process start ticks")
	}
	return fields[0][0], fields[19], nil
}
