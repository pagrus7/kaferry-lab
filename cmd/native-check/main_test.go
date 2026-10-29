package main

import (
	"strings"
	"testing"
)

func TestNativeCheckArgumentsCannotSelectAnotherCommand(t *testing.T) {
	base := []string{"--repository=/home/labrunner/kaferry-native-ci-synthetic/source", "--run-id=synthetic",
		"--reviewed-head=" + strings.Repeat("a", 40), "--input-sha256=" + strings.Repeat("b", 64)}
	if _, err := parse(base); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{{"--command=/bin/false"}, {"/bin/false"}, {"--owned-native-check-anchor"}} {
		if _, err := parse(append(append([]string{}, base...), extra...)); err == nil {
			t.Fatal("caller selected an alternate command/anchor through normal plan")
		}
	}
	for _, missing := range [][]string{nil, base[:3], {"--owned-native-check-anchor", "unexpected"}} {
		if _, err := parse(missing); err == nil {
			t.Fatal("incomplete caller inputs accepted")
		}
	}
}
