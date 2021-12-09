//go:build linux

package commandrun

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"
)

const (
	MAX_PATH_LEN = 4096
)

type ptraceContext struct {
	parentPid   int
	mainProgram string
	processes   map[int]*ProcessInfo
	exitCode    int
}

func enableTracing(c *exec.Cmd) {
	c.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}
}

func (r *CommandRun) trace(c *exec.Cmd) ([]ProcessInfo, error) {
	ctx := &ptraceContext{
		parentPid:   c.Process.Pid,
		mainProgram: c.Path,
		processes:   make(map[int]*ProcessInfo),
	}

	if err := ctx.runTrace(); err != nil {
		return nil, err
	}

	r.ExitCode = ctx.exitCode

	if ctx.exitCode != 0 {
		return ctx.procInfoArray(), fmt.Errorf("exit status %v", ctx.exitCode)
	}

	return ctx.procInfoArray(), nil
}

func (ctx *ptraceContext) runTrace() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status := unix.WaitStatus(0)
	_, err := unix.Wait4(ctx.parentPid, &status, 0, nil)
	if err != nil {
		return err
	}

	if err := unix.PtraceSetOptions(ctx.parentPid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		return err
	}

	procInfo := ctx.getProcInfo(ctx.parentPid)
	procInfo.Program = ctx.mainProgram
	if err := unix.PtraceSyscall(ctx.parentPid, 0); err != nil {
		return err
	}

	for {
		pid, err := unix.Wait4(-1, &status, 0, nil)
		if err != nil {
			return err
		}

		if pid == ctx.parentPid && status.Exited() {
			ctx.exitCode = status.ExitStatus()
			return nil
		}

		if status.Stopped() {
			ctx.nextSyscall(pid)
		}
	}
}

func (ctx *ptraceContext) nextSyscall(pid int) error {
	regs := unix.PtraceRegs{}
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		return err
	}

	if msg == unix.PTRACE_EVENTMSG_SYSCALL_ENTRY {
		if err := ctx.handleSyscall(pid, regs); err != nil {
			return err
		}
	}

	return unix.PtraceSyscall(pid, 0)
}

func (ctx *ptraceContext) handleSyscall(pid int, regs unix.PtraceRegs) error {
	switch regs.Orig_rax {
	case unix.SYS_EXECVE:
		program, err := ctx.readSyscallReg(pid, uintptr(regs.Rdi), MAX_PATH_LEN)
		if err != nil {
			return err
		}

		procInfo := ctx.getProcInfo(pid)
		procInfo.Program = program

	case unix.SYS_OPENAT:
		file, err := ctx.readSyscallReg(pid, uintptr(regs.Rsi), MAX_PATH_LEN)
		if err != nil {
			return err
		}

		procInfo := ctx.getProcInfo(pid)
		procInfo.OpenedFiles[file] = procInfo.OpenedFiles[file] + 1
	}

	return nil
}

func (ctx *ptraceContext) getProcInfo(pid int) *ProcessInfo {
	procInfo, ok := ctx.processes[pid]
	if !ok {
		procInfo = &ProcessInfo{
			ProcessID:   pid,
			OpenedFiles: make(map[string]int),
		}

		ctx.processes[pid] = procInfo
	}

	return procInfo
}

func (ctx *ptraceContext) procInfoArray() []ProcessInfo {
	processes := make([]ProcessInfo, 0)
	for _, procInfo := range ctx.processes {
		processes = append(processes, *procInfo)
	}

	return processes
}

func (ctx *ptraceContext) readSyscallReg(pid int, addr uintptr, n int) (string, error) {
	data := make([]byte, n)
	localIov := unix.Iovec{
		Base: &data[0],
		Len:  uint64(n),
	}

	removeIov := unix.RemoteIovec{
		Base: addr,
		Len:  n,
	}

	// ProcessVMReadv is much faster than PtracePeekData since it doesn't route the data through kernel space,
	// but there may be times where this doesn't work.  We may want to fall back to PtracePeekData if this fails
	numBytes, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{removeIov}, 0)
	if err != nil {
		return "", err
	}

	if numBytes == 0 {
		return "", nil
	}

	// don't want to use cgo... look for the first 0 byte for the end of the c string
	size := bytes.IndexByte(data, 0)
	return string(data[:size]), nil
}
