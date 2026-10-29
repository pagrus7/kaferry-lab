//go:build linux

package campaign

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

func nativeCheckPlatform() error {
	if runtime.GOARCH != "arm64" || runtime.Version() != "go1.26.0" || os.Getuid() != 501 || os.Geteuid() != 501 {
		return errors.New("exact Go1.26.0 native Linux ARM64 uid501 required")
	}
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return err
	}
	text := func(chars []int8) string {
		var body []byte
		for _, c := range chars {
			if c == 0 {
				break
			}
			body = append(body, byte(c))
		}
		return string(body)
	}
	if text(u.Nodename[:]) != nativeCheckMachine || text(u.Release[:]) != "7.0.14-orbstack-00380-ga7e0a2dc9535" || text(u.Machine[:]) != "aarch64" {
		return errors.New("fixed owned native machine/kernel pair required")
	}
	return nil
}
