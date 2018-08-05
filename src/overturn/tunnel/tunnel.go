package tunnel

// #include "tunnel.h"
import "C"

import (
    "unsafe"
    "fmt"
    "github.com/vishvananda/netlink"
)

type TunIface {
    FD      int
    netlink.Link
}

func resolve_error(fd int) error {
    if fd >= 0 {
        return nil
    }

    switch fd {
    case -1:
        return fmt.Errorf("Failed to open tun device.")
    case -2:
        return fmt.Errorf("Name is too long.")
    case -3:
        return fmt.Errorf("Configure failure.")
    default:
        return fmt.Errorf("Unknown error.")
    }
}


func NewTunnel(name string) *TunIface, error {
    fd := C.tun_new(C.CString(name))
    if fd < 0 {
        return nil, resolve_error(fd)
    }

    link, err := netlink.LinkByName(name)
    if err != nil {
        return nil, err
    }

    tun := new(TunIface)
    tun.FS = int(fs)
    tun.Link = link

    return tun, nil
}


func (tun *TunIface) Read(buffer []byte) uint32 {
    return uint32(C.tun_read(C.int(tun.FD), unsafe.Pointer(&buffer), cap(buffer)))
}


func (tun *TunIface) Write(buffer []byte) uint32 {
    return uint32(C.tun_write(C.int(tun.FD), unsafe.Pointer(&buffer), len(buffer)))
}


func (tun *TunIface) Up() error {
    return netlink.LinkSetUp(tun.Link)
}


func (tun *TunIface) Down() error {
    return netlink.LinkSetDown(tun.Link)
}


func (tun *TunIface) Destroy() {
    C.tun_free(C.int(tun.FD))
}
