package fixture

import (
	"context"
	"errors"
	"os"
	"time"
)

// DirectAbsence is a read-only observation after cleanup, not a second cleanup
// attempt. Its retained receipt cannot attest its writer's own final close.
type DirectAbsence struct {
	RunID, NetworkID, PrivateReference string
	BrokerIDs                          []string
	ContainersAbsent                   [2]bool
	NetworkAbsent, Complete            bool
}

// ObserveDirectAbsence reads only the complete receipt's two container IDs and
// network ID. A present resource, warning, refused command or lost sink fails;
// this function never removes anything and never guesses a partial setup ID.
func ObserveDirectAbsence(ctx context.Context, s State, raw Executor) (r DirectAbsence, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, err := validatedDirectIdentity(s)
	if err != nil {
		return r, err
	}
	r = DirectAbsence{RunID: s.RunID, NetworkID: id.NetworkID, BrokerIDs: append([]string(nil), id.BrokerIDs...)}
	run, err := FixtureExecutor(s, raw)
	if err != nil {
		return r, err
	}
	control, err := os.CreateTemp(directPrivateDirectory(s.RunID), "absence-control-*.json")
	if err != nil {
		return r, errors.Join(err, StopFixtureEvidence(s, "direct absence diagnostic reservation failed"))
	}
	defer func() {
		finishImageControl(control, s, "direct read-only absence observation incomplete", &err)
		if err != nil {
			r.Complete = false
		}
	}()
	for i, target := range id.BrokerIDs {
		_, present, e := inspectDirectContainerRaw(ctx, run, target)
		if e != nil || present {
			return r, errors.Join(e, errors.New("retained direct container absence not proven"))
		}
		r.ContainersAbsent[i] = true
	}
	_, present, err := inspectDirectNetwork(ctx, s, run, id.NetworkID)
	if err != nil || present {
		return r, errors.Join(err, errors.New("retained direct network absence not proven"))
	}
	r.NetworkAbsent = true
	if err = ctx.Err(); err != nil {
		return r, err
	}
	r.Complete = true
	r.PrivateReference, err = writeLinkPrivate(directPrivateDirectory(s.RunID), "", r)
	return r, err
}
