package ovtd

import (
	"overturn/protocol"

	"fmt"
	log "github.com/Sirupsen/logrus"
	"net"
	"runtime"
	"sync/atomic"
	"time"
)

// Tunnel

type ICMPTunnel struct {
	//DataIn          chan []*protocol.OVTPacket
	//DataOut         chan []*protocol.OVTPacket

	MaxWorker int
	RxStat    uint64
	WxStat    uint64
	MTU       uint32

	worker_count uint32
	running      uint32
	conn         net.PacketConn
	sigStop      chan int
}

type Handler func(tun *ICMPTunnel, pkt *protocol.OVTPacket)

func NewICMPTunnel(address string) (*ICMPTunnel, error) {
	var err error
	tun := new(ICMPTunnel)

	tun.MaxWorker = runtime.NumCPU()
	tun.worker_count = 0
	tun.RxStat = 0
	tun.WxStat = 0
	tun.MTU = 1464 // Header: IP(20byte) + ICMP(8Byte) + OVT(8Byte)
	//tun.DataOut = nil
	//tun.DataIn = make(chan []byte, tun.MaxWorker)
	tun.sigStop = make(chan int)

	tun.conn, err = net.ListenPacket("ip4:icmp", address)
	if err != nil {
		return nil, err
	}
	return tun, nil
}

func (tun *ICMPTunnel) Destroy() error {
	tun.Stop()
	return tun.conn.Close()
}

func (tun *ICMPTunnel) addReader(handler Handler) error {
	if tun.MaxWorker > 0 && tun.worker_count >= uint32(tun.MaxWorker) {
		return fmt.Errorf("Maximum number of worker reached.")
	}

	atomic.AddUint32(&tun.worker_count, 1)
	go func() {
		var pkt *protocol.OVTPacket
		var is_encap bool

		buf := make([]byte, tun.MTU+28+protocol.OVT_HEADER_SIZE)

		for tun.running > 0 {
			now := time.Now()
			tun.conn.SetReadDeadline(now.Add(1000000000))
			sz, _, err := tun.conn.ReadFrom(buf)
			if err != nil {
				var op_err *net.OpError
				var is_err bool
				op_err, is_err = err.(*net.OpError)

				if is_err && op_err.Timeout() {
					continue
				}
			}

			is_encap, pkt, err = protocol.OVTPacketUnpack(buf[:sz], 65536)
			if is_encap {
				if err != nil {
					log.WithFields(log.Fields{
						"module":     "ICMPTunnel",
						"event":      "packet",
						"err_detail": err.Error(),
					}).Warningf("Invalid packet. Drop.")
					continue
				}
				atomic.AddUint64(&tun.RxStat, uint64(len(*pkt))-protocol.OVT_HEADER_SIZE)

				handler(tun, pkt)
				//tun.DataOut <- pkt
			}
		}

		last := atomic.AddUint32(&tun.worker_count, 0xFFFFFFFF) // -1
		if last == 0 {
			tun.sigStop <- 0
		}
	}()

	return nil
}

func (tun *ICMPTunnel) Write(packet protocol.OVTPacket, address net.Addr) (int, error) {
	wx, err := tun.conn.WriteTo(packet, address)
	atomic.AddUint64(&tun.WxStat, uint64(wx))
	return wx, err
}

func (tun *ICMPTunnel) Start() error {
	//var worker_count int

	//if tun.MaxWorker < -1 {
	//	worker_count = runtime.NumCPU()
	//} else {
	//	worker_count = tun.MaxWorker
	//}

	//tun.DataOut = make(chan []byte, tun.MaxWorker)

	//for ; worker_count > 0; worker_count-- {
	//	err := tun.addReader()
	//	if err != nil {
	//		return err
	//	}
	//}

	// Stat logger here

	return nil
}

func (tun *ICMPTunnel) Stop() error {
	for {
		running := tun.running
		if running == 0 {
			return fmt.Errorf("Not running.")
		}
		if atomic.CompareAndSwapUint32(&tun.running, running, 0) {
			break
		}
	}

	//close(tun.DataOut)

	// wait until all readers are stopped
	<-tun.sigStop

	//tun.DataOut = nil
	return nil
}
