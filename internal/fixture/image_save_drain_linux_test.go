//go:build linux

package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const imageDrainStdout = "PRIVATE held-pipe archive prefix\x00\xff"
const imageDrainStderr = "PRIVATE held-pipe stderr prefix\x00\xff"

type imageDrainIdentity struct {
	PID, ParentPID int
	StartTicks     uint64
	State          string
	Stdout, Stderr string
}

func imageDrainKernelIdentity(pid int, descriptors bool) (imageDrainIdentity, error) {
	result := imageDrainIdentity{PID: pid}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return result, err
	}
	end := strings.LastIndex(string(raw), ") ")
	if end < 0 {
		return result, errors.New("owned helper proc stat framing invalid")
	}
	fields := strings.Fields(string(raw[end+2:]))
	if len(fields) < 20 {
		return result, errors.New("owned helper proc stat incomplete")
	}
	result.State = fields[0]
	result.ParentPID, err = strconv.Atoi(fields[1])
	if err != nil {
		return result, err
	}
	result.StartTicks, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return result, err
	}
	if descriptors {
		result.Stdout, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/1", pid))
		if err != nil {
			return result, err
		}
		result.Stderr, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/2", pid))
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func imageDrainEnvironment(role, directory string) []string {
	return []string{"LC_ALL=C", "KAFERRY_SAVE_DRAIN_ROLE=" + role, "KAFERRY_SAVE_DRAIN_DIRECTORY=" + directory, "GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
}

func imageDrainWriteJSON(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) > 64<<10 {
		return errors.New("owned drain control JSON bound exceeded")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return persistLinkPrivateReceipt(f, append(body, '\n'))
}

// This process owns only the inherited stdout/stderr write ends and its own
// finite lifetime. It neither signals processes nor launches another child.
func TestImageSaveDrainPipeHolderSpecimen(t *testing.T) {
	if os.Getenv("KAFERRY_SAVE_DRAIN_ROLE") != "holder" {
		return
	}
	directory := os.Getenv("KAFERRY_SAVE_DRAIN_DIRECTORY")
	identity, err := imageDrainKernelIdentity(os.Getpid(), true)
	if err == nil {
		err = imageDrainWriteJSON(filepath.Join(directory, "holder-identity.json"), identity)
	}
	if err == nil {
		f, e := os.OpenFile(filepath.Join(directory, "holder-ready"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			err = e
		} else {
			err = f.Close()
		}
	}
	if err != nil {
		_, _ = os.Stderr.Write([]byte(err.Error()))
		os.Exit(23)
	}
	// This exceeds the selected controller's two-second post-wait drain, yet
	// supplies natural bounded cleanup without signalling any PID or group.
	time.Sleep(7 * time.Second)
	os.Exit(0)
}

type imageDrainLaunch struct {
	Producer, Holder imageDrainIdentity
	HolderPID        int
	Cause            []byte
}

// The separate control FD is never an oracle from selected stdout/stderr. The
// producer closes it on exec in its child, so only the selected data pipes are
// deliberately inherited. PID comes from this producer's actual Cmd.Start.
func TestImageSaveDrainProducerSpecimen(t *testing.T) {
	if os.Getenv("KAFERRY_SAVE_DRAIN_ROLE") != "producer" {
		return
	}
	go func() { time.Sleep(12 * time.Second); os.Exit(31) }()
	syscall.CloseOnExec(3)
	control := os.NewFile(3, "owned-save-drain-control")
	if control == nil {
		os.Exit(24)
	}
	directory := os.Getenv("KAFERRY_SAVE_DRAIN_DIRECTORY")
	frame := imageDrainLaunch{}
	var err error
	frame.Producer, err = imageDrainKernelIdentity(os.Getpid(), true)
	exe := ""
	if err == nil {
		exe, err = os.Executable()
	}
	var holder *exec.Cmd
	if err == nil {
		holder = exec.Command(exe, "-test.run=^TestImageSaveDrainPipeHolderSpecimen$")
		holder.Env = imageDrainEnvironment("holder", directory)
		holder.Stdout, holder.Stderr = os.Stdout, os.Stderr
		err = holder.Start()
		if err == nil {
			frame.HolderPID = holder.Process.Pid
			frame.Holder, err = imageDrainKernelIdentity(frame.HolderPID, true)
		}
	}
	if err == nil {
		deadline := time.Now().Add(2 * time.Second)
		for {
			_, e := os.Lstat(filepath.Join(directory, "holder-ready"))
			if e == nil {
				break
			}
			if !errors.Is(e, os.ErrNotExist) {
				err = e
				break
			}
			if time.Now().After(deadline) {
				err = errors.New("owned pipe holder did not reach ready boundary")
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if err == nil {
		n, e := os.Stdout.Write([]byte(imageDrainStdout))
		err = e
		if err == nil && n != len(imageDrainStdout) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		n, e := os.Stderr.Write([]byte(imageDrainStderr))
		err = e
		if err == nil && n != len(imageDrainStderr) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		frame.Cause = []byte(err.Error())
	}
	body, encodeErr := json.Marshal(frame)
	if encodeErr == nil {
		body = append(body, '\n')
	}
	n, writeErr := control.Write(body)
	if writeErr == nil && n != len(body) {
		writeErr = io.ErrShortWrite
	}
	closeErr := control.Close()
	if encodeErr != nil || writeErr != nil || closeErr != nil {
		// The original parent still has its known child handle if the separate
		// custody channel failed. Consume that actual finite wait here; never
		// ask the controller to clean a guessed or unreported PID.
		if holder != nil && holder.Process != nil {
			_ = holder.Wait()
		}
		os.Exit(25)
	}
	if err != nil {
		os.Exit(23)
	}
	// Deliberately omit holder.Wait: the isolated controller subreaper must
	// observe adoption and consume this exact child's real terminal status.
	os.Exit(0)
}

type imageDrainWait struct {
	RequestedPID, ReturnedPID  int
	RawStatus                  uint32
	Terminal, Exited, Signaled bool
	ExitCode                   int
	ElapsedNanoseconds         int64
	Usage                      syscall.Rusage
	ConsumedWaitConfirmed      bool
	ConsumedWaitReturnedPID    int
	ConsumedWaitErrno          uint64
}

func imageDrainWaitHolder(pid int, start uint64, controller int) (imageDrainWait, error) {
	result := imageDrainWait{RequestedPID: pid}
	// A surfaced identity-read error is retained and stays nonpassing. The
	// known direct-child handle reported over the private control FD still
	// permits this exact kernel child wait for cleanup; no signal or alternate
	// identity read follows that error.
	identity, identityErr := imageDrainKernelIdentity(pid, false)
	if identityErr == nil && (identity.StartTicks != start || identity.ParentPID != controller) {
		identityErr = errors.New("owned adopted holder identity changed before exact wait")
	}
	started := time.Now()
	deadline := started.Add(10 * time.Second)
	for {
		var status syscall.WaitStatus
		var usage syscall.Rusage
		returned, err := syscall.Wait4(pid, &status, syscall.WNOHANG, &usage)
		if err != nil {
			return result, errors.Join(identityErr, err)
		}
		if returned == pid {
			result.ReturnedPID = returned
			result.RawStatus = uint32(status)
			result.Usage = usage
			result.Terminal = status.Exited() || status.Signaled()
			result.Exited = status.Exited()
			result.Signaled = status.Signaled()
			result.ExitCode = status.ExitStatus()
			result.ElapsedNanoseconds = time.Since(started).Nanoseconds()
			var after syscall.WaitStatus
			again, afterErr := syscall.Wait4(pid, &after, syscall.WNOHANG, nil)
			result.ConsumedWaitReturnedPID = again
			var waitErrno syscall.Errno
			if errors.As(afterErr, &waitErrno) {
				result.ConsumedWaitErrno = uint64(waitErrno)
			}
			result.ConsumedWaitConfirmed = again == -1 && errors.Is(afterErr, syscall.ECHILD)
			if !result.Terminal || !result.ConsumedWaitConfirmed {
				return result, errors.New("actual holder terminal wait or consumed-wait observation missing")
			}
			return result, identityErr
		}
		if returned != 0 {
			return result, errors.New("exact holder wait returned an unexpected PID")
		}
		if time.Now().After(deadline) {
			return result, errors.New("owned finite holder terminal wait exceeded budget")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type imageDrainControlResult struct {
	Synthetic, SaveRejected, DrainReached, NoFalseEOF, StopRetained, NoRetry, AdoptionObserved, ControlPassed bool
	ControllerPID, ProducerPID                                                                                int
	ProducerRawStatus                                                                                         uint32
	SaveElapsedNanoseconds                                                                                    int64
	Launch                                                                                                    imageDrainLaunch
	LaunchRaw, ExpectedSaveCause                                                                              []byte
	HolderAfterSave, HolderSelf                                                                               imageDrainIdentity
	HolderWait                                                                                                imageDrainWait
	Save                                                                                                      imageSaveReceipt
	StopSHA256Before, StopSHA256After                                                                         string
	Causes                                                                                                    [][]byte
}

// PR_SET_CHILD_SUBREAPER is confined to this dedicated one-shot subprocess.
// The ordinary shared go-test process never changes that process attribute.
func TestImageSaveDrainControllerSpecimen(t *testing.T) {
	if os.Getenv("KAFERRY_SAVE_DRAIN_ROLE") != "controller" {
		return
	}
	directory := os.Getenv("KAFERRY_SAVE_DRAIN_DIRECTORY")
	go func() { time.Sleep(20 * time.Second); os.Exit(32) }()
	result := imageDrainControlResult{Synthetic: true, ControllerPID: os.Getpid()}
	var failures []error
	add := func(err error) {
		if err != nil {
			failures = append(failures, err)
			result.Causes = append(result.Causes, []byte(err.Error()))
		}
	}
	defer func() {
		if err := imageDrainWriteJSON(filepath.Join(directory, "controller-result.json"), result); err != nil {
			t.Error("owned drain result persistence failed")
		}
		if len(failures) != 0 {
			t.Error("owned save drain control failed; exact private causes retained if sink available")
		}
	}()
	if err := os.Chdir(directory); err != nil {
		add(err)
		return
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		add(err)
		return
	}
	value := int32(-1)
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&value)), 0, 0, 0, 0)
	if errno != 0 {
		add(errno)
		return
	}
	if value != 1 {
		add(errors.New("isolated controller subreaper readback missing"))
		return
	}
	s := nativeImageState(t)
	if err := reserveLinkEvidence(s.RunID); err != nil {
		add(err)
		return
	}
	read, write, err := os.Pipe()
	if err != nil {
		add(err)
		return
	}
	defer read.Close()
	exe, err := os.Executable()
	if err != nil {
		add(errors.Join(err, write.Close()))
		return
	}
	var producer *exec.Cmd
	calls := 0
	factory := imageSaveCommand(func(ctx context.Context, _ ...string) *exec.Cmd {
		calls++
		producer = exec.CommandContext(ctx, exe, "-test.run=^TestImageSaveDrainProducerSpecimen$")
		producer.Env = imageDrainEnvironment("producer", directory)
		producer.ExtraFiles = []*os.File{write}
		return producer
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	started := time.Now()
	saveErr := ensureSavedImages(context.WithValue(ctx, imageSaveCommandKey{}, factory), s)
	result.SaveElapsedNanoseconds = time.Since(started).Nanoseconds()
	cancel()
	add(write.Close())
	if err = read.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		add(err)
	}
	frame, frameErr := io.ReadAll(io.LimitReader(read, (16<<10)+1))
	result.LaunchRaw = append([]byte(nil), frame...)
	add(frameErr)
	if len(frame) > 16<<10 {
		add(errors.New("owned drain control channel exceeds bound"))
	}
	if frameErr == nil {
		add(json.Unmarshal(frame, &result.Launch))
	}
	if len(result.Launch.Cause) != 0 {
		add(errors.New("owned producer prerequisite failed; exact cause retained in launch frame"))
	}
	// Cleanup precedes all assertions after a child was launched. Only this
	// separately reported direct-child PID/start identity can authorize wait4.
	if result.Launch.HolderPID > 1 && result.Launch.Holder.PID == result.Launch.HolderPID && result.Launch.Holder.StartTicks > 0 {
		result.HolderAfterSave, err = imageDrainKernelIdentity(result.Launch.HolderPID, true)
		add(err)
		result.AdoptionObserved = err == nil && result.HolderAfterSave.ParentPID == os.Getpid() && result.HolderAfterSave.StartTicks == result.Launch.Holder.StartTicks && result.HolderAfterSave.State != "Z" && result.HolderAfterSave.State != "X" && result.HolderAfterSave.Stdout == result.Launch.Holder.Stdout && result.HolderAfterSave.Stderr == result.Launch.Holder.Stderr
		result.HolderWait, err = imageDrainWaitHolder(result.Launch.HolderPID, result.Launch.Holder.StartTicks, os.Getpid())
		add(err)
	} else {
		add(errors.New("owned holder identity unavailable for exact adopted wait"))
	}
	holderBody, holderReadErr := readImagePrivateFile(filepath.Join(directory, "holder-identity.json"), 64<<10)
	add(holderReadErr)
	if holderReadErr == nil {
		add(json.Unmarshal(holderBody, &result.HolderSelf))
	}
	result.SaveRejected = saveErr != nil
	if saveErr != nil {
		result.ExpectedSaveCause = []byte(saveErr.Error())
	}
	if producer != nil && producer.ProcessState != nil {
		result.ProducerPID = producer.ProcessState.Pid()
		if status, ok := producer.ProcessState.Sys().(syscall.WaitStatus); ok {
			result.ProducerRawStatus = uint32(status)
		}
	}
	raw, err := readImagePrivateFile(filepath.Join(linkPrivateDirectory(s.RunID), "image-save-attempt.json"), 256<<10)
	add(err)
	if err == nil {
		add(json.Unmarshal(raw, &result.Save))
	}
	result.DrainReached = saveErr != nil && strings.Contains(saveErr.Error(), "image save pipe EOF not observed within drain budget") && result.SaveElapsedNanoseconds >= int64(2*time.Second)
	result.NoFalseEOF = !result.Save.StdoutEOF && !result.Save.StderrEOF && !result.Save.Complete
	stopPath := filepath.Join(linkPrivateDirectory(s.RunID), "STOPPED.json")
	before, err := readImagePrivateFile(stopPath, 256<<10)
	add(err)
	result.StopRetained = err == nil
	result.StopSHA256Before = linkDigest(before)
	secondErr := ensureSavedImages(context.WithValue(context.Background(), imageSaveCommandKey{}, factory), s)
	dockerCalls := 0
	_, executorErr := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) { dockerCalls++; return nil, nil })
	after, err := readImagePrivateFile(stopPath, 256<<10)
	add(err)
	result.StopSHA256After = linkDigest(after)
	result.NoRetry = secondErr != nil && executorErr != nil && calls == 1 && dockerCalls == 0 && bytes.Equal(before, after)
	archive, err := readImagePrivateFile(savedImageArchivePath(s), imageArchiveLimit)
	add(err)
	if !bytes.Equal(archive, []byte(imageDrainStdout)) || !bytes.Equal(result.Save.Stderr, []byte(imageDrainStderr)) {
		add(errors.New("selected original stdout/stderr prefix not retained exactly"))
	}
	_, completionErr := os.Lstat(filepath.Join(linkPrivateDirectory(s.RunID), "image-save-complete.json"))
	if !errors.Is(completionErr, os.ErrNotExist) {
		add(errors.Join(errors.New("failed drain produced complete save receipt"), completionErr))
	}
	if _, err = validatedImageSaveReceipt(s); err == nil {
		add(errors.New("failed drain admitted complete image save proof"))
	}
	launch := result.Launch
	if launch.Producer.PID != result.ProducerPID || launch.Producer.ParentPID != os.Getpid() || launch.Holder.ParentPID != launch.Producer.PID || result.HolderSelf.PID != launch.Holder.PID || result.HolderSelf.StartTicks != launch.Holder.StartTicks || result.HolderSelf.ParentPID != launch.Producer.PID || result.HolderSelf.Stdout != launch.Holder.Stdout || result.HolderSelf.Stderr != launch.Holder.Stderr || launch.Producer.StartTicks == 0 || launch.Producer.Stdout != launch.Holder.Stdout || launch.Producer.Stderr != launch.Holder.Stderr || !strings.HasPrefix(launch.Holder.Stdout, "pipe:[") || !strings.HasPrefix(launch.Holder.Stderr, "pipe:[") {
		add(errors.New("actual producer/holder ancestry or pipe origin mismatch"))
	}
	status := syscall.WaitStatus(result.ProducerRawStatus)
	if !result.Save.Started || !result.Save.WaitReturned || !result.Save.TerminalWait || !result.Save.ArchiveClosed || result.Save.ExitCode == nil || *result.Save.ExitCode != 0 || !status.Exited() || status.ExitStatus() != 0 {
		add(errors.New("selected producer actual successful terminal wait missing"))
	}
	if !result.SaveRejected || !result.DrainReached || !result.NoFalseEOF || !result.StopRetained || !result.NoRetry || !result.AdoptionObserved || !result.HolderWait.Terminal || !result.HolderWait.Exited || result.HolderWait.ExitCode != 0 || !result.HolderWait.ConsumedWaitConfirmed {
		add(errors.New("reached drain failure or bounded actual cleanup evidence missing"))
	}
	result.ControlPassed = len(failures) == 0
}

func TestImageSaveDescendantHeldPipeDrain(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("owned native drain control requires reviewed Linux architecture")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("native drain repository unavailable")
	}
	module, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil || !strings.HasPrefix(string(module), "module github.com/pagrus7/kaferry-lab\n") {
		t.Fatal("native drain control requires package working directory")
	}
	root := filepath.Join(repo, ".cache", "m2", "native-return-20261028", "save-drain-control")
	if err = os.MkdirAll(root, 0700); err != nil {
		t.Fatal("private native drain storage unavailable")
	}
	rootInfo, rootErr := os.Lstat(root)
	if rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 {
		t.Fatal("native drain storage is not an owner-only directory")
	}
	rootOwner, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootOwner.Uid != uint32(os.Geteuid()) {
		t.Fatal("native drain storage owner mismatch")
	}
	directory, err := os.MkdirTemp(root, "native-")
	if err != nil {
		t.Fatal("private native drain attempt unavailable")
	}
	coverage := filepath.Join(directory, "coverage")
	if err = os.Mkdir(coverage, 0700); err != nil {
		t.Fatal("owned coverage directory unavailable")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("native drain helper executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Second)
	defer cancel()
	child, cancelOutput := context.WithCancel(ctx)
	defer cancelOutput()
	output := &linkBoundedOutput{cancel: cancelOutput}
	cmd := exec.CommandContext(child, exe, "-test.run=^TestImageSaveDrainControllerSpecimen$", "-test.v")
	cmd.Env = []string{"LC_ALL=C", "KAFERRY_SAVE_DRAIN_ROLE=controller", "KAFERRY_SAVE_DRAIN_DIRECTORY=" + directory, "GOCOVERDIR=" + coverage}
	cmd.WaitDelay = time.Second
	cmd.Stdout, cmd.Stderr = output, output
	started := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(started)
	var cause []byte
	if runErr != nil {
		cause = []byte(runErr.Error())
	}
	receipt := struct {
		Argv                         []string
		Cause, Combined              []byte
		ObservedBytes                int64
		ElapsedNanoseconds           int64
		DirectWaitReturned, Terminal bool
		PID                          int
		RawStatus                    uint32
	}{Argv: cmd.Args, Cause: cause, Combined: output.bytes, ObservedBytes: output.observed, ElapsedNanoseconds: elapsed.Nanoseconds(), DirectWaitReturned: cmd.ProcessState != nil}
	if cmd.ProcessState != nil {
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			receipt.Terminal = status.Exited() || status.Signaled()
			receipt.RawStatus = uint32(status)
			receipt.PID = cmd.ProcessState.Pid()
		}
	}
	if err = imageDrainWriteJSON(filepath.Join(directory, "outer-command.json"), receipt); err != nil {
		t.Fatal("native drain outer receipt unavailable")
	}
	if runErr != nil || output.overflow || !receipt.DirectWaitReturned || !receipt.Terminal {
		t.Fatal("owned drain controller failed; preserve private attempt", directory)
	}
	body, err := readImagePrivateFile(filepath.Join(directory, "controller-result.json"), 64<<10)
	if err != nil {
		t.Fatal("native drain result unavailable", directory)
	}
	var result imageDrainControlResult
	if json.Unmarshal(body, &result) != nil || !result.Synthetic || !result.ControlPassed || !result.SaveRejected || !result.DrainReached || !result.NoFalseEOF || !result.NoRetry || !result.AdoptionObserved || !result.HolderWait.Terminal || !result.HolderWait.ConsumedWaitConfirmed {
		t.Fatal("native drain control evidence did not pass", directory)
	}
	t.Log("synthetic reached drain failure and exact natural cleanup retained", directory)
}
