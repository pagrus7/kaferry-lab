//go:build linux

package campaign

import (
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/identity"
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
	return nativeProcessArchitecture(runtime.GOARCH, machine.String())
}

// Native means the reviewed Go target and Linux kernel architecture agree.
// In particular an AMD64 executable on an ARM64 kernel is translated.
func nativeProcessArchitecture(goarch, machine string) error {
	if (goarch == "amd64" && machine == "x86_64") || (goarch == "arm64" && machine == "aarch64") {
		return nil
	}
	return errors.New("release campaign requires matching reviewed native Linux Go and kernel architectures")
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

// SysUsage is the accounting retained by os.ProcessState for this exact waited
// child, not RUSAGE_CHILDREN or a process enumeration. Linux ru_maxrss is KiB;
// timeval CPU fields are seconds plus microseconds:
// https://www.man7.org/linux/man-pages/man2/getrusage.2.html
// https://pkg.go.dev/os#ProcessState.SysUsage
func processUsageFromState(state *os.ProcessState) processResourceUsage {
	if state == nil {
		return linuxProcessUsage(nil)
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok {
		return processResourceUsage{Source: "os.ProcessState.SysUsage/Linux-rusage", Scope: processUsageScope, Error: "wait resource accounting has an unsupported Linux representation"}
	}
	return linuxProcessUsage(usage)
}
func linuxProcessUsage(usage *syscall.Rusage) processResourceUsage {
	result := processResourceUsage{Source: "os.ProcessState.SysUsage/Linux-rusage", Scope: processUsageScope}
	if usage == nil {
		result.Error = "wait resource accounting is unavailable"
		return result
	}
	rssKiB := int64(usage.Maxrss)
	if rssKiB <= 0 || rssKiB > math.MaxInt64/1024 {
		result.Error = "wait peak RSS is missing, negative or exceeds the supported byte range"
		return result
	}
	user, err := linuxCPUTime(usage.Utime)
	if err != nil {
		result.Error = "invalid waited user CPU time: " + err.Error()
		return result
	}
	system, err := linuxCPUTime(usage.Stime)
	if err != nil {
		result.Error = "invalid waited system CPU time: " + err.Error()
		return result
	}
	result.Available = true
	result.PeakRSSKiB = identity.Int64(rssKiB)
	result.PeakRSSBytes = identity.Int64(rssKiB * 1024)
	result.UserCPUNanoseconds = identity.Int64(user)
	result.SystemCPUNanoseconds = identity.Int64(system)
	return result
}
func linuxCPUTime(value syscall.Timeval) (int64, error) {
	sec, usec := int64(value.Sec), int64(value.Usec)
	if sec < 0 || usec < 0 || usec >= 1_000_000 || sec > math.MaxInt64/int64(time.Second) {
		return 0, errors.New("invalid seconds/microseconds or nanosecond overflow")
	}
	seconds := sec * int64(time.Second)
	if usec > (math.MaxInt64-seconds)/int64(time.Microsecond) {
		return 0, errors.New("nanosecond overflow")
	}
	return seconds + usec*int64(time.Microsecond), nil
}
