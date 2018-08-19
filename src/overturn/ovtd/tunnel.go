package ovtd

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"os"
	"sync/atomic"
	"time"
)

type LinkTunnel struct {
	Link netlink.Tuntap

	RxStat uint64
	WxStat uint64

	worker_count uint32
	reader_index uint32
	running      uint32
	stopSig      chan int
}

func NewLinkTunnel(name string, queues int) (*LinkTunnel, error) {
	var err error

	tun := &LinkTunnel{Link: netlink.Tuntap{
		LinkAttrs:  netlink.NewLinkAttrs(),
		Mode:       netlink.TUNTAP_MODE_TUN,
		Flags:      0,
		NonPersist: true,
		Queues:     queues,
		Fds:        nil,
	},
		RxStat:       0,
		WxStat:       0,
		worker_count: 0,
		reader_index: 0,
		running:      1,
		stopSig:      make(chan int),
	}

	tun.Link.LinkAttrs.Name = name
	err = netlink.LinkAdd(&tun.Link)
	if err != nil {
		return nil, err
	}

	return tun, nil
}

func (tun *LinkTunnel) Handler(handler func(tun *LinkTunnel, data []byte)) error {
	atomic.AddUint32(&tun.worker_count, 1)
	reader_idx := atomic.AddUint32(&tun.reader_index, 1) - 1

	go func() {
		last_mtu := tun.Link.Attrs().MTU

		buf := make([]byte, last_mtu+4)
		for tun.running > 0 {
			fd := tun.Link.Fds[reader_idx%uint32(len(tun.Link.Fds))]
			now := time.Now()
			fd.SetReadDeadline(now.Add(1000000000))
			size, err := fd.Read(buf)

			if err != nil {
				sys_err, ok := err.(*os.SyscallError)
				if ok && sys_err.Timeout() {
					log.WithFields(log.Fields{
						"module":     "LinkTunnel",
						"err_detail": err.Error(),
					}).Error("Error occurs when reading from tunnel interface.")
				}
				continue
			}

			atomic.AddUint64(&tun.RxStat, uint64(size))
			handler(tun, buf[:size])

			// reallocate buffer if MTU is changed
			this_mtu := tun.Link.Attrs().MTU
			if this_mtu != last_mtu {
				buf = make([]byte, this_mtu+4)
				last_mtu = this_mtu
			}
		}

		new_count := atomic.AddUint32(&tun.worker_count, 0xFFFFFFFF) // -1
		if new_count == 0 {
			tun.stopSig <- 0
		}
	}()

	return nil
}

func (tun *LinkTunnel) ReaderCount() uint32 {
	return tun.worker_count
}

func (tun *LinkTunnel) WxClear() uint64 {
	return atomic.SwapUint64(&tun.WxStat, 0)
}

func (tun *LinkTunnel) RxClear() uint64 {
	return atomic.SwapUint64(&tun.RxStat, 0)
}

func (tun *LinkTunnel) Close(buf []byte) error {
	return netlink.LinkDel(&tun.Link)
}

func (tun *LinkTunnel) SetMTU(mtu int) error {
	return netlink.LinkSetMTU(&tun.Link, mtu)
}

func (tun *LinkTunnel) Up() error {
	return netlink.LinkSetUp(&tun.Link)
}

func (tun *LinkTunnel) Down() error {
	return netlink.LinkSetDown(&tun.Link)
}

func (tun *LinkTunnel) Stop() error {
	var last uint32

	for {
		last = tun.running
		if last == 0 {
			return errors.New("Tunnel not running.")
		}
		if atomic.CompareAndSwapUint32(&tun.running, last, 0) {
			break
		}
	}

	<-tun.stopSig
	return tun.Down()
}

func (tun *LinkTunnel) Start() error {
	var last uint32

	for {
		last = tun.running
		if last > 0 {
			return errors.New("Tunnel is running.")
		}
		if atomic.CompareAndSwapUint32(&tun.running, last, 1) {
			break
		}
	}

	// start stat logger here

	return tun.Up()
}

func (tun *LinkTunnel) SetWriteDeadline(fd_index uint, t time.Time) error {
	file := tun.Link.Fds[fd_index%uint(len(tun.Link.Fds))]
	return file.SetDeadline(t)
}

func (tun *LinkTunnel) Write(buf []byte, fd_index uint) (int, error) {
	file := tun.Link.Fds[fd_index%uint(len(tun.Link.Fds))]
	return file.Write(buf)
}
