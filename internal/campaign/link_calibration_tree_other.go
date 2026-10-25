//go:build !linux

package campaign

import (
	"context"
	"errors"
	"os/exec"
)

// No alternative process topology on unsupported hosts.
type linkCalibrationGroup struct{ result LinkCalibrationTree }

func prepareLinkCalibrationTree() (LinkCalibrationTree, error) {
	return LinkCalibrationTree{}, errors.New("link calibration child ownership requires native Linux")
}
func startLinkCalibrationGroup(*exec.Cmd, LinkCalibrationTree) (*linkCalibrationGroup, error) {
	return nil, errors.New("link calibration process groups require Linux")
}
func (*linkCalibrationGroup) attach(*exec.Cmd) error {
	return errors.New("link calibration process groups require Linux")
}
func (*linkCalibrationGroup) checkMember(int) error {
	return errors.New("link calibration process groups require Linux")
}
func (*linkCalibrationGroup) beginStop() error {
	return errors.New("link calibration process groups require Linux")
}
func (*linkCalibrationGroup) lastSignal() error {
	return errors.New("link calibration process groups require Linux")
}
func (g *linkCalibrationGroup) close(context.Context, bool) (LinkCalibrationTree, error) {
	return g.result, errors.New("link calibration child waits require Linux")
}
func drainLinkCalibrationChildren(context.Context, LinkCalibrationTree) (LinkCalibrationTree, error) {
	return LinkCalibrationTree{}, errors.New("link calibration child waits require Linux")
}
