// +build cgo
// +build !386

package sha1

/*
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

struct sockaddr_alg sha1_sa = {
  .salg_family = AF_ALG,
  .salg_type = "hash",
  .salg_name = "sha1"
};
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

func New() (Hasher, error) {
	return newAfalg()
}

type afalg struct {
	tfm_fd int
	op_fd  int
	mtx    sync.Mutex
}

func newAfalg() (a *afalg, err error) {
	a = &afalg{tfm_fd: -1, op_fd: -1}
	runtime.SetFinalizer(a, func(a *afalg) {
		a.Close()
	})
	a.tfm_fd, err = syscall.Socket(syscall.AF_ALG, syscall.SOCK_SEQPACKET, 0)
	if err != nil || a.tfm_fd == -1 {
		a.Close()
		return nil, fmt.Errorf("failed creating af_alg socket: %v", err)
	}

	// rats, we can't call Bind with a sockaddr_alg. There's no sockaddr_alg
	// in the go stdlib, nor can i make up my own byte array that matches
	// the required sockaddr interface in the bind call. have to use cgo.
	if C.bind(C.int(a.tfm_fd), (*C.struct_sockaddr)(unsafe.Pointer(&C.sha1_sa)),
		C.socklen_t(unsafe.Sizeof(C.sha1_sa))) != 0 {
		a.Close()
		return nil, fmt.Errorf("failed binding af_alg connection")
	}

	// can't call Accept with go's stdlib, cause it's going to make up and
	// pass a sockaddr to fill in. not only do we not care about the sockaddr,
	// the sockaddr type is sockaddr_alg, and go doesn't understand that.
	nfd, _, e := syscall.Syscall(syscall.SYS_ACCEPT, uintptr(a.tfm_fd), 0, 0)
	a.op_fd = int(nfd)
	if e != 0 || a.op_fd == -1 {
		a.Close()
		return nil, fmt.Errorf("failed accepting af_alg connection: %v", e)
	}
	return a, nil
}

func (a *afalg) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return 0, nil
	}

	// rats, go doesn't have a plain old send. the man page for the standard C
	// call for send says sendto is identical, but with a null target address.
	// go's stdlib assumes a non-nil sockaddr arg. so we have to make the
	// syscall ourselves.
	// additionally, because of this, i386 is hard. 6-argument syscalls are
	// different on i386 and SYS_SENDTO doesn't exist.
	_, _, e := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(a.op_fd),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(syscall.MSG_MORE), 0, 0)
	if e != 0 {
		return 0, e
	}
	return len(data), nil
}

func (a *afalg) Sum() (md [Size]byte, err error) {
	n, err := syscall.Read(a.op_fd, md[:])
	if err != nil {
		return md, err
	}
	if n != Size {
		return md, fmt.Errorf("invalid sha1 length")
	}
	return md, nil
}

func (a *afalg) Close() {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.op_fd != -1 {
		syscall.Close(a.op_fd)
		a.op_fd = -1
	}
	if a.tfm_fd != -1 {
		syscall.Close(a.tfm_fd)
		a.tfm_fd = -1
	}
	runtime.SetFinalizer(a, nil)
}
