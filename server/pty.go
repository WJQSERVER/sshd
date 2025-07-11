package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// PtyRun 启动一个伪终端 (pty) 并将命令附加到它.
func PtyRun(c *exec.Cmd, tty *os.File) error {
	defer tty.Close()
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	if err := c.Start(); err != nil {
		return fmt.Errorf("pty run cmd start failed: %w", err)
	}
	return nil
}

// parseDims 从字节缓冲区中解析窗口尺寸.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

type WindowSize struct {
	Height uint16
	Width  uint16
}

// SetWindowSize 设置给定 pty 文件描述符的大小.
func SetWindowSize(fd uintptr, w, h uint32) {
	ws := &WindowSize{Width: uint16(w), Height: uint16(h)}
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
	if err != 0 {
		log.Printf("设置窗口大小失败: %v", err)
	}
}
