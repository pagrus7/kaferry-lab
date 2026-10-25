package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// RetainLinkNetworkFailure is the private notice boundary for the lab's linked
// in-process HTTP/TCP controls. Callers supply the actual action and retain their
// own timing. A successful write does not classify or authorize a retry, prove
// the action succeeded, or make raw evidence safe to publish. Completeness
// flags concern the supplied bytes fitting these bounds, not complete HTTP/TCP
// streams; callers must identify partial reads/prefixes in action/cause facts.
// This owner-only local sink does not provide a durable publication channel.
func RetainLinkNetworkFailure(s State, action []string, notice []byte, cause error) (reference string, err error) {
	if err = validateLinkPlan(s); err != nil {
		return "", errors.New("link network evidence requires validated linked state")
	}
	root := linkPrivateDirectory(s.RunID)
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("private link network evidence directory unavailable")
	}
	marker := filepath.Join(root, "PRIVATE.json")
	info, e = os.Lstat(marker)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return "", errors.New("private link network reservation unavailable")
	}
	body, e := os.ReadFile(marker)
	var reservation struct{ RunID string }
	if e != nil || json.Unmarshal(body, &reservation) != nil || reservation.RunID != s.RunID {
		return "", errors.New("private link network reservation does not match run")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, stopLinkOperation(s.RunID, "linked network evidence incomplete"))
		}
	}()
	actionBytes := 0
	for _, part := range action {
		actionBytes += len(part)
	}
	if len(action) == 0 || len(action) > 128 || actionBytes > 32<<10 {
		return "", errors.New("link network action exceeds evidence bound")
	}
	causeBytes := []byte(nil)
	if cause != nil {
		causeBytes = []byte(cause.Error())
	}
	noticeBytes, causeLength := len(notice), len(causeBytes)
	noticeComplete, causeComplete := noticeBytes <= linkOutputLimit, causeLength <= linkOutputLimit
	if !noticeComplete {
		notice = notice[:linkOutputLimit]
	}
	if !causeComplete {
		causeBytes = causeBytes[:linkOutputLimit]
	}
	safeCause := safeLinkDockerCause(context.Background(), cause)
	receipt := struct {
		RunID                                   string
		Action                                  []string
		Classification                          string
		Notice, CauseText                       []byte
		NoticeSHA256, CauseSHA256               string
		ReportedNoticeBytes, ReportedCauseBytes int
		NoticeComplete, CauseComplete           bool
		Cause                                   linkDockerCause
	}{s.RunID, append([]string(nil), action...), "PRIVATE RAW EVIDENCE", notice, causeBytes, linkDigest(notice), linkDigest(causeBytes), noticeBytes, causeLength, noticeComplete, causeComplete, safeCause}
	reference, e = writeLinkPrivate(root, "", receipt)
	if e != nil {
		return reference, e
	}
	summary := struct {
		RunID, PrivateReference, NoticeSHA256, CauseSHA256 string
		ReportedNoticeBytes, ReportedCauseBytes            int
		NoticeComplete, CauseComplete                      bool
		Cause                                              linkDockerCause
	}{s.RunID, reference, linkDigest(notice), linkDigest(causeBytes), noticeBytes, causeLength, noticeComplete, causeComplete, safeCause}
	if e = linkReceipt(s, "network-failure", summary); e != nil {
		return reference, errors.New("public link network summary persistence failed")
	}
	if !noticeComplete || !causeComplete {
		return reference, errors.New("link network notice incomplete; operation stopped")
	}
	return reference, nil
}
