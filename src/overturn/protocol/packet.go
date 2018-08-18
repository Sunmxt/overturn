package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/ipv4"
	"math/rand"
)

// Packet Encapsulation
type OVTPacket []byte

//type OVTPacket struct {
//	icmp.Message
//	data []byte
//}

var (
	OVT_MAGIC = [4]byte{'O', 'V', 'T', 0xAA}
)

const (
	OVT_HEADER_SIZE  = 8
	ICMP_HEADER_SIZE = 8
	IP_HEADER_SIZE   = 20

	OFFSET_OVT_HEADER = ICMP_HEADER_SIZE

	PKG_TOO_SHORT = "Packet too short."
	PKG_INVALID   = "Not a OVTPacket."
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
	pack := make(OVTPacket, payload_size+OVT_HEADER_SIZE+ICMP_HEADER_SIZE)
	pack[0] = byte(ipv4.ICMPTypeEchoReply) // Type
	pack[1] = byte(0)                      // Code
	pack[2] = byte(0)                      // Checksum
	pack[3] = byte(0)
	binary.BigEndian.PutUint32(pack[4:6], rand.Uint32())
	binary.BigEndian.PutUint32(pack[6:8], rand.Uint32())
	copy(pack[OFFSET_OVT_HEADER:OFFSET_OVT_HEADER+4], OVT_MAGIC[:])
	return &pack
}

func OVTPacketUnpack(buf []byte, size_limit uint32) (bool, OVTPacket, error) {

	if len(buf) < OFFSET_OVT_HEADER+4 {
		return false, nil, errors.New(PKG_TOO_SHORT)
	}
	if bytes.Equal(buf[OFFSET_OVT_HEADER:OFFSET_OVT_HEADER+4], OVT_MAGIC[:]) {
		return false, nil, errors.New(PKG_INVALID)
	}
	if len(buf) < OFFSET_OVT_HEADER+8 {
		return true, nil, errors.New(PKG_TOO_SHORT)
	}
	enc_len := binary.BigEndian.Uint32(buf[OFFSET_OVT_HEADER+4 : OFFSET_OVT_HEADER+8])
	if enc_len+OFFSET_OVT_HEADER != uint32(len(buf)) {
		return true, nil, fmt.Errorf("Payload size unmatched. (buffered: %v, encoded: %v)", len(buf), enc_len)
	}
	if enc_len+OFFSET_OVT_HEADER > size_limit {
		return true, nil, fmt.Errorf("Packet size limited for safety.")
	}

	pkt := NewOVTPacket(uint(enc_len - OVT_HEADER_SIZE))
	copy(pkt.PayloadRef(), buf[OVT_HEADER_SIZE:])
	return true, pkt, nil
}

func (pack OVTPacket) MagicRef() OVTPacket {
	return pack[OFFSET_OVT_HEADER : OFFSET_OVT_HEADER+4]
}

func (pack OVTPacket) Pack() []byte {
	var enc_len uint32

	pack_len := len(pack)
	if pack_len >= ICMP_HEADER_SIZE {
		enc_len = uint32(pack_len)
	} else {
		enc_len = 0
	}

	binary.BigEndian.PutUint32(pack[OFFSET_OVT_HEADER+4:OFFSET_OVT_HEADER+8], enc_len-ICMP_HEADER_SIZE)
	s := checksum(pack)
	pack[2] ^= byte(s)
	pack[3] ^= byte(s >> 8)
	return []byte(pack)
}

func (pack OVTPacket) PayloadRef() []byte {
	return pack[OFFSET_OVT_HEADER+4 : OFFSET_OVT_HEADER+4+len(pack)-ICMP_HEADER_SIZE]
}
