package ovtd

import (
	"overturn/protocol"

	"encoding/binary"
	"fmt"
	//log "github.com/Sirupsen/logrus"
	"net"
	//"runtime"
	"errors"
	"golang.org/x/net/ipv4"
	"math/rand"
	"sync/atomic"
	"time"
)

// Tunnel

type ICMPTunnel struct {
	//DataIn          chan []*protocol.OVTPacket
	//DataOut         chan []*protocol.OVTPacket

	RxStat uint64
	WxStat uint64
	MTU    uint32

	worker_count uint32
	running      uint32
	conn         net.PacketConn
	sigStop      chan int
}

const (
	ICMP_HEADER_SIZE = 8
)

type ICMPTunnelPacket []byte

//type NetTunnel interface {
//    NewPacket(payload_size uint32) protocol.TunnelPacket
//    Write(packet protocol.TunnelPacket) (int, error)
//    Handler(handler func(packet protocol.TunnelPacket))
//    Start() error
//    Stop() error
//}

func (pkt ICMPTunnelPacket) PayloadRef() []byte {
	return pkt[ICMP_HEADER_SIZE:]
}

func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

func (tun *ICMPTunnel) NewPacket(payload_size uint) protocol.TunnelPacket {
	pack := make(ICMPTunnelPacket, payload_size+ICMP_HEADER_SIZE)
	pack[0] = byte(ipv4.ICMPTypeEchoReply) // Type
	pack[1] = byte(0)                      // Code
	pack[2] = byte(0)                      // Checksum
	pack[3] = byte(0)
	binary.BigEndian.PutUint16(pack[4:6], uint16(rand.Uint32()&0xFFFF))
	binary.BigEndian.PutUint16(pack[6:8], uint16(rand.Uint32()&0xFFFF))
	return &pack
}

func NewICMPTunnel(address string) (*ICMPTunnel, error) {
	var err error
	tun := new(ICMPTunnel)

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

func (tun *ICMPTunnel) Handler(handler func(tun *ICMPTunnel, pkt protocol.TunnelPacket)) error {

	atomic.AddUint32(&tun.worker_count, 1)
	go func() {
		buf := make([]byte, tun.MTU-20)

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

			if ipv4.ICMPType(buf[0]) != ipv4.ICMPTypeEchoReply && ipv4.ICMPType(buf[0]) != ipv4.ICMPTypeEcho {
				continue
			}

			atomic.AddUint64(&tun.RxStat, uint64(sz))
			handler(tun, ICMPTunnelPacket(buf[:sz]))
		}

		last := atomic.AddUint32(&tun.worker_count, 0xFFFFFFFF) // -1
		if last == 0 {
			tun.sigStop <- 0
		}
	}()

	return nil
}

func (tun *ICMPTunnel) Write(packet protocol.TunnelPacket, address net.Addr) (int, error) {
	pkt, ok := packet.(*ICMPTunnelPacket)
	if !ok {
		return 0, errors.New("Not a icmp tunnel packet")
	}

	s := checksum((*pkt)[:])
	(*pkt)[2] ^= byte(s)
	(*pkt)[3] ^= byte(s >> 8)

	wx, err := tun.conn.WriteTo((*pkt)[:], address)
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
	for {
		running := tun.running
		if running > 0 {
			return nil
		}
		if atomic.CompareAndSwapUint32(&tun.running, 0, 1) {
			break
		}
	}

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
