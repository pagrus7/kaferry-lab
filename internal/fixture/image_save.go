package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const imageArchiveLimit int64 = 512 << 20

type imageSaveCommand func(context.Context, ...string) *exec.Cmd
type imageSaveCommandKey struct{}

type imageSaveReceipt struct {
	RunID                                                                                           string
	Argv, ExecutedArgv                                                                              []string
	ExecutablePath                                                                                  string
	StartedAt, EndedAt                                                                              time.Time
	Started, WaitReturned, TerminalWait, StdoutEOF, StderrEOF, PipesClosed, ArchiveClosed, Complete bool
	ArchiveBytes, ObservedArchiveBytes, ObservedStderrBytes                                         int64
	Stderr, Cause                                                                                   []byte
	CauseComplete                                                                                   bool
	ExitCode                                                                                        *int
}

func imageDataDirectory(s State) string {
	return filepath.Join(".cache", "image-identity-data", s.RunID)
}
func savedImageArchivePath(s State) string { return filepath.Join(imageDataDirectory(s), "images.tar") }

func imageSaveArgv(s State) []string {
	args := []string{"docker", "image", "save", "--platform=linux/arm64", Image}
	if s.Proxy != nil {
		args = append(args, arm64ProxyImage)
	}
	return args
}

type imageSaveWriter struct {
	writer                   io.Writer
	limit, observed, written int64
	cancel                   context.CancelFunc
}

func (w *imageSaveWriter) Write(p []byte) (int, error) {
	w.observed += int64(len(p))
	allowed := w.limit - w.written
	if int64(len(p)) > allowed {
		if allowed > 0 {
			n, err := w.writer.Write(p[:allowed])
			w.written += int64(n)
			if n != int(allowed) && err == nil {
				err = io.ErrShortWrite
			}
			if err != nil {
				w.cancel()
				return n, err
			}
		}
		w.cancel()
		return int(allowed), errors.New("image save stream exceeds fixed bound")
	}
	n, err := w.writer.Write(p)
	w.written += int64(n)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.cancel()
	}
	return n, err
}

// This fixed command has its own archive route. It never uses or enlarges the
// JSON command capture executor. The direct Cmd.Wait and both pipe readers are
// accounted separately; a descendant-held pipe cannot claim EOF or completion.
func executeImageSave(ctx context.Context, s State, f *os.File, makeCommand imageSaveCommand) (receipt imageSaveReceipt, err error) {
	child, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	receipt.RunID = s.RunID
	receipt.Argv = imageSaveArgv(s)
	receipt.StartedAt = time.Now().UTC()
	outR, outW, e := os.Pipe()
	if e != nil {
		return receipt, e
	}
	errR, errW, e := os.Pipe()
	if e != nil {
		return receipt, errors.Join(e, outR.Close(), outW.Close())
	}
	cmd := makeCommand(child, receipt.Argv[1:]...)
	receipt.ExecutablePath = cmd.Path
	receipt.ExecutedArgv = append([]string(nil), cmd.Args...)
	cmd.Stdout, cmd.Stderr = outW, errW
	e = cmd.Start()
	writeCloseErr := errors.Join(outW.Close(), errW.Close())
	if e != nil {
		err = errors.Join(e, writeCloseErr, outR.Close(), errR.Close())
		receipt.PipesClosed = true
		receipt.EndedAt = time.Now().UTC()
		return receipt, err
	}
	receipt.Started = true
	archive := &imageSaveWriter{writer: f, limit: imageArchiveLimit, cancel: cancel}
	var stderr imageStderrBuffer
	diagnostic := &imageSaveWriter{writer: &stderr, limit: linkOutputLimit, cancel: cancel}
	type streamResult struct {
		err    error
		closed error
	}
	outDone, errDone := make(chan streamResult, 1), make(chan streamResult, 1)
	go func() { _, e := io.Copy(archive, outR); outDone <- streamResult{e, outR.Close()} }()
	go func() { _, e := io.Copy(diagnostic, errR); errDone <- streamResult{e, errR.Close()} }()
	waitErr := cmd.Wait()
	receipt.WaitReturned = true
	if cmd.ProcessState != nil {
		receipt.TerminalWait = cmd.ProcessState.Exited()
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			receipt.TerminalWait = status.Exited() || status.Signaled()
		}
		code := cmd.ProcessState.ExitCode()
		receipt.ExitCode = &code
	}
	// Fresh bounded drain interval after the actual direct-child wait.
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	var outResult, errResult streamResult
	outReceived, errReceived := false, false
	var drainErr error
	for !outReceived || !errReceived {
		select {
		case outResult = <-outDone:
			outReceived = true
			receipt.StdoutEOF = outResult.err == nil
		case errResult = <-errDone:
			errReceived = true
			receipt.StderrEOF = errResult.err == nil
		case <-timer.C:
			drainErr = errors.New("image save pipe EOF not observed within drain budget")
			if !outReceived {
				_ = outR.Close()
				outResult = <-outDone
				outReceived = true
			}
			if !errReceived {
				_ = errR.Close()
				errResult = <-errDone
				errReceived = true
			}
		}
	}
	receipt.PipesClosed = outResult.closed == nil && errResult.closed == nil
	receipt.ArchiveBytes, receipt.ObservedArchiveBytes, receipt.ObservedStderrBytes = archive.written, archive.observed, diagnostic.observed
	receipt.Stderr = append([]byte(nil), stderr.body...)
	receipt.EndedAt = time.Now().UTC()
	err = errors.Join(waitErr, writeCloseErr, outResult.err, outResult.closed, errResult.err, errResult.closed, drainErr, child.Err())
	return receipt, err
}

type imageStderrBuffer struct{ body []byte }

func (b *imageStderrBuffer) Write(p []byte) (int, error) {
	b.body = append(b.body, p...)
	return len(p), nil
}

func ensureSavedImages(ctx context.Context, s State) (err error) {
	root, err := imagePrivateAuthority(s)
	if err != nil {
		return err
	}
	completePath := filepath.Join(root, "image-save-complete.json")
	if _, e := os.Lstat(completePath); e == nil {
		_, err = validatedImageSaveReceipt(s)
		if err != nil {
			err = errors.Join(err, stopImageOperation(s, "retained image save lifecycle invalid"))
		}
		return err
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	control, err := os.CreateTemp(root, "image-save-control-*.json")
	if err != nil {
		return errors.Join(err, stopImageOperation(s, "image save diagnostic reservation failed"))
	}
	defer finishImageControl(control, s, "native image save incomplete", &err)
	// The stop is reserved BEFORE filesystem or command mutations; a crash,
	// partial stream or sink refusal leaves the selected facility stopped.
	if _, err = writeLinkPrivate(root, "STOPPED.json", struct{ RunID, Operation string }{s.RunID, "fixed native image save pending"}); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(imageDataDirectory(s)), 0700); err != nil {
		return err
	}
	parent, statErr := os.Lstat(filepath.Dir(imageDataDirectory(s)))
	if statErr != nil {
		return statErr
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parent.Mode().Perm() != 0700 || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("private image data parent identity rejected")
	}
	if err = os.Mkdir(imageDataDirectory(s), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(savedImageArchivePath(s), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	makeCommand, _ := ctx.Value(imageSaveCommandKey{}).(imageSaveCommand)
	if makeCommand == nil {
		makeCommand = func(ctx context.Context, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "docker", args...)
		}
	}
	receipt, runErr := executeImageSave(ctx, s, f, makeCommand)
	closeErr := errors.Join(f.Sync(), f.Close())
	receipt.ArchiveClosed = closeErr == nil
	err = errors.Join(runErr, closeErr)
	if err != nil {
		receipt.Cause = []byte(err.Error())
		receipt.CauseComplete = len(receipt.Cause) <= linkOutputLimit
		if !receipt.CauseComplete {
			receipt.Cause = receipt.Cause[:linkOutputLimit]
		}
	}
	receipt.Complete = err == nil && receipt.Started && receipt.TerminalWait && receipt.WaitReturned && receipt.StdoutEOF && receipt.StderrEOF && receipt.PipesClosed && receipt.ArchiveClosed
	if _, persistErr := writeLinkPrivate(root, "image-save-attempt.json", receipt); persistErr != nil {
		return errors.Join(err, persistErr)
	}
	if !receipt.Complete {
		return errors.Join(err, errors.New("native image save incomplete; facility stopped"))
	}
	if _, err = writeLinkPrivate(root, "image-save-complete.json", receipt); err != nil {
		return err
	}
	return os.Remove(filepath.Join(root, "STOPPED.json"))
}

func parseSavedImage(s State, fixed fixedModernImage) (imageArchiveResult, error) {
	var empty imageArchiveResult
	save, err := validatedImageSaveReceipt(s)
	if err != nil {
		return empty, err
	}
	info, err := os.Lstat(imageDataDirectory(s))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return empty, errors.Join(errors.New("saved image directory unavailable"), err)
	}
	dirOwner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || dirOwner.Uid != uint32(os.Geteuid()) {
		return empty, errors.New("saved image directory owner rejected")
	}
	f, err := os.OpenFile(savedImageArchivePath(s), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, err
	}
	before, err := f.Stat()
	if err != nil {
		return empty, errors.Join(err, f.Close())
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || before.Size() <= 0 || before.Size() > imageArchiveLimit {
		return empty, errors.Join(errors.New("saved image file identity/bound rejected"), f.Close())
	}
	result, parseErr := readImageArchive(f, imageArchiveExpected{Manifest: fixed.manifest, Config: fixed.config, OS: "linux", Architecture: "arm64"})
	after, statErr := f.Stat()
	closeErr := f.Close()
	if err = errors.Join(parseErr, statErr, closeErr); err != nil {
		return result, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || result.ArchiveBytes != before.Size() || result.ArchiveBytes != save.ArchiveBytes || !result.Complete {
		return empty, errors.New("saved archive changed or parse incomplete")
	}
	return result, nil
}

// Reuse requires the retained command lifecycle and a fresh bounded archive
// hash/identity check. A proof's Complete label cannot replace these checks.
func validatedImageSaveReceipt(s State) (imageSaveReceipt, error) {
	var receipt imageSaveReceipt
	body, err := readImagePrivateFile(filepath.Join(imageEvidenceDirectory(s), "image-save-complete.json"), 256<<10)
	if err != nil {
		return receipt, err
	}
	if err = decodeImageArchiveJSON(body, &receipt); err != nil {
		return imageSaveReceipt{}, err
	}
	argv := imageSaveArgv(s)
	if receipt.RunID != s.RunID || !receipt.Complete || !receipt.Started || !receipt.WaitReturned || !receipt.TerminalWait || !receipt.StdoutEOF || !receipt.StderrEOF || !receipt.PipesClosed || !receipt.ArchiveClosed || receipt.ExitCode == nil || *receipt.ExitCode != 0 || receipt.ArchiveBytes <= 0 || receipt.ArchiveBytes > imageArchiveLimit || receipt.ObservedArchiveBytes != receipt.ArchiveBytes || len(receipt.Stderr) != 0 || receipt.ObservedStderrBytes != 0 || len(receipt.Cause) != 0 || filepath.Base(receipt.ExecutablePath) != "docker" || len(receipt.Argv) != len(argv) || len(receipt.ExecutedArgv) != len(argv) {
		return imageSaveReceipt{}, errors.New("retained native image save lifecycle is incomplete or conflicting")
	}
	for i := range argv {
		if receipt.Argv[i] != argv[i] || receipt.ExecutedArgv[i] != argv[i] {
			return imageSaveReceipt{}, errors.New("retained native image save command differs from fixed selection")
		}
	}
	return receipt, nil
}

// One pre-reserved diagnostic retains an available exact first cause. A failed
// append/sync/close is returned and latched; no second sink or rewrite follows.
func finishImageControl(f *os.File, s State, operation string, outcome *error) {
	var cause []byte
	complete := true
	if *outcome != nil {
		cause = []byte((*outcome).Error())
		complete = len(cause) <= linkOutputLimit
		if !complete {
			cause = cause[:linkOutputLimit]
		}
	}
	body, encodeErr := json.Marshal(struct {
		RunID, Operation string
		Cause            []byte
		CauseComplete    bool
	}{s.RunID, operation, cause, complete})
	*outcome = errors.Join(*outcome, encodeErr, persistLinkPrivateReceipt(f, append(body, '\n')))
	if *outcome != nil {
		*outcome = errors.Join(*outcome, stopImageOperation(s, operation))
	}
}
