//go:build !linux

package campaign

import "errors"

func nativeCheckPlatform() error {
	return errors.New("native harness check requires the selected Linux ARM64 guest")
}
