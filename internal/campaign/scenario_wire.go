package campaign

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

// The optional wire experiment does not contribute a qualification trigger.
// The capture/decoder's own Supported and CompletenessEstablished fields stay
// false until their separate native acceptance and sensitivity controls pass.
func (c *scenarioController) startWire(ctx context.Context) error {
	c.report.Limitations = append(c.report.Limitations, "Experimental packet decoding retains candidates only; threshold reach and capture completeness remain unsupported.")
	start := time.Now()
	capture, err := startWireCapture(ctx, wirePlan{Directory: filepath.Join(c.plan.Directory, "runtime", "wire"), ToolReceipt: c.plan.WireToolReceipt, Duration: 3 * time.Minute, MaxBytes: 32 << 20}, c.destination)
	c.wire = capture
	return errors.Join(err, c.retain(scenarioObservation{Kind: "experimental_wire_start", Interval: c.interval(start), Error: scenarioError(err)}))
}
func (c *scenarioController) finishWire(ctx context.Context) error {
	if c.wire == nil {
		return nil
	}
	start := time.Now()
	capture := c.wire
	c.wire = nil
	receipt, err := capture.Stop()
	err = errors.Join(err, c.retain(scenarioObservation{Kind: "experimental_wire_stop", Interval: c.interval(start), WireCapture: &receipt, Error: scenarioError(err)}))
	if err != nil {
		return err
	}
	known := []wireKnownValue{}
	for _, input := range c.k.Inputs {
		if input.LogicalID == nil {
			continue
		}
		value, e := input.Record.Value.Bytes()
		if e != nil {
			return e
		}
		routes, e := kafkaAllowedPartitions(c.plan.Routing, input, c.k.Preparation.Destination.Partitions)
		if e != nil {
			return e
		}
		if len(routes) != 1 {
			return errors.New("stress record has no unique independently derived wire route")
		}
		known = append(known, wireKnownValue{ID: input.ID, Topic: c.k.Preparation.Destination.Topic, Partition: int(routes[0]), Value: value})
	}
	start = time.Now()
	// The exact producer client ID follows the reviewed release's documented
	// prefix plus the explicit destination client.id in the retained SQL.
	decoded, err := capture.Decode(ctx, "kaferry-lab-m2", known)
	return errors.Join(err, c.retain(scenarioObservation{Kind: "experimental_wire_candidates", Interval: c.interval(start), WireCandidates: &decoded, Error: scenarioError(err)}))
}
