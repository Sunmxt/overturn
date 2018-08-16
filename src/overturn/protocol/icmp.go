package protocol

import (
    "encoding/binary"
    "net/icmp"
    "net/ipv4"
    "math/rand"
    "errors"
    "fmt"
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


