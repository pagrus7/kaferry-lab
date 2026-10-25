package campaign

import "github.com/pagrus7/kaferry-lab/internal/evidence"

// Wait accounting belongs to the single owned child reaped by Cmd.Wait.
type processResourceUsage = evidence.M2ResourceUsage

const processUsageScope = evidence.M2ProcessUsageScope
