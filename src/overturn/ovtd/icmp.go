package ovtd

import (
    "net/icmp"
    "net/ipv4"
    "math/rand"
    "errors"
    "runtime"
    "encoding/binary"
    "sync/atomic"
    "fmt"
    "time"
    log "github.com/sirupsen/logrus"
)

// Packet Encapsulation

type OVTPacket struct {
    icmp.Message
    data        []byte
}

const (
    OVT_MAGIC = [4]byte{'O', 'V', 'T', 0xAA}

    OVT_HEADER_SIZE     = 8
    ICMP_HEADER_SIZE    = 8
    IP_HEADER_SIZE      = 20

    OFFSET_OVT_HEADER   = ICMP_HEADER_SIZE
    
    PKG_TOO_SHORT = "Packet too short."
    PKG_INVALID = "Not a OVTPacket."
)


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

func NewOVTPacket(payload_size uint) OVTPacket {
    pack := make(OVTPacket, payload_size + OVT_HEADER_SIZE + ICMP_HEADER_SIZE)
    pack[0] = byte(int(ipv4.ICMPType))     // Type
    pack[1] = byte(0)                      // Code
    pack[2] = byte(0)                      // Checksum
    pack[3] = byte(0)
    binary.BigEndian.PutUint32(pack.data[4:6], rand.Uint32())
    binary.BigEndian.PutUint32(pack.data[6:8], rand.Uint32())
    copy(pack.data[OFFSET_OVT_HEADER: OFFSET_OVT_HEADER + 4], OVT_MAGIC)
    return pack
}

func OVTPacketUnpack(buf byte[], size_limit uint32) *OVTPacket, error {
    if len(buf) < OFFSET_OVT_HEADER + 4 {
        return false, nil, errors.New(PKG_TOO_SHORT)
    }
    if buf[OFFSET_OVT_HEADER: OFFSET_OVT_HEADER + 4] != OVT_MAGIC {
        return false, nil, errors.New(PKG_INVALID)
    }
    if len(buf) < OFFSET_OVT_HEADER + 8 {
        return true, nil, errors.New(PKG_TOO_SHORT)
    }
    enc_len := binary.BigEndian.Uint32(buf[OFFSET_OVT_HEADER + 4: OFFSET_OVT_HEADER + 8])
    if enc_len != len(buf) - OFFSET_OVT_HEADER {
        return true, nil, fmt.Errorf("Payload size unmatched. (buffered: %v, encoded: %v)", len(buf), enc_len)
    }

    pkt := NewOVTPacket(enc_len - OVT_HEADER_SIZE)
    copy(pkt.PayloadRef, buf[OVT_HEADER_SIZE:])
    return pkt
}

func (pack OVTPacket) MagicRef() OVTPacket {
    return pack[OFFSET_OVT_HEADER: OFFSET_OVT_HEADER + 4]
}

func (pack OVTPacket) Pack() []byte {
    binary.BigEndian.PutUint32(pack.data[OFFSET_OVT_HEADER + 4: OFFSET_OVT_HEADER + 8], len(pack) - ICMP_HEADER_SIZE)
    s := checksum(pack)
    pack[2] ^= byte(s)
    pack[3] ^= byte(s >> 8)
    return []byte(OVTPacket)
}

func (pack OVTPacket) PayloadRef() []byte {
    return pack[OFFSET_OVT_HEADER + 4: OFFSET_OVT_HEADER + 4 + len(OVTPacket) - ICMP_HEADER_SIZE]
}


// Tunnel
type ICMPTunnel struct {
    DataIn          chan []*OVTPacket
    DataOut         chan []*OVTPacket
    MaxWorker       int
    RxStat          uint64
    WxStat          uint64
    MTU             uint32

    worker_count    uint32
    running         uint32    
    conn            icmp.PacketConn
    sigStop         chan int
}


func NewICMPTunnel(address string) ICMPTunnel, error {
    var err error
    tun := new(ICMPTunnel)

    tun.MaxWorker = runtime.NumCPU()
    tun.worker_count = 0
    tun.RxStat = 0
    tun.WxStat = 0
    tun.MTU = 1464 // Header: IP(20byte) + ICMP(8Byte) + OVT(8Byte)
    tun.DataOut = nil
    tun.DataIn = make(chan []byte, tun.MaxWorker)
    tun.sigStop = make(chan int)
    
    tun.conn, err = net.ListenPacket("ip4:icmp", address)
    if err != nil {
        return nil, err
    }
    return tun
}

func (tun *ICMPTunnel) Destroy() error {
    tun.Stop()
    return tun.conn.Close()
}

func (tun *ICMPTunnel) addReader() error {
    if tun.MaxWorker > 0 && len(tun.worker) >= tun.MaxWorker {
        return fmt.Errorf("Maximum number of worker reached.")
    }

    atomic.AddUint32(&tun.worker_count, 1)
    go func() {
        var err error, pkt *OVTPacket, is_encap bool

        buf := make([]byte, tun.MTU + 28 + OVT_HEADER_SIZE)

        for tun.running {
            now := timer.Now()
            tun.conn.SetReadDeadline(now.Add(1000000000))
            sz, from, err := tun.conn.ReadFrom(buf)

            is_encap , pkt, err = OVTPacketUnpack(buf)
            if is_encap {
                if err != nil {
                    log.WithFields(log.Fields{
                            "module" : "ICMPTunnel",
                            "event" : "packet",
                            "err_detail" : "",
                        }).Warningf("Invalid packet. Drop.")
                    continue
                }
                atomic.AddUint64(&tun.RxStat, len(*pkt) - OVT_HEADER_SIZE)

                tun.DataOut <- pkt
            }
        }

        last := atomic.AddUint32(&tun.worker_count, uint32(-1))
        if last == 0 {
            tun.stopStop <- 0
        }
    }

    return nil
}

func (tun *ICMPTunnel) Write(packet OVTPacket, address net.Addr) int, error {
    wx, err := tun.conn.WriteTo(packet, address)
    atomic.AddUint64(&tun.WxStat, wx)
    return wx, err
}

func (tun *ICMPTunnel) Start() error {
    var worker_count int

    if tun.MaxWorker < -1 {
        worker_count = runtime.NumCPU()
    } else {
        worker_count = tun.MaxWorker
    }

    tun.DataOut = make(chan []byte, tun.MaxWorker)
    
    for ; worker_count > 0 ; worker_count-- {
        err := tun.addReader()
        if err != nil {
            return err
        }
    }
    return nil
}

func (tun *ICMPTunneler) Stop() error {
    for {
        running := tun.running
        if running == 0 {
            return fmt.Errorf("Not running.")
        }
        if atomic.CompareAndSwapUint32(&tun.running, running, 0) {
            break
        }
    }

    close(tun.DataOut)

    // wait until all readers are stopped
    <- tun.sigStop

    tun.DataOut = nil    
}
