package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Packet Encapsulation
type OVTPacket []byte

type OVTEncapsulatedPacket interface {
	OVTPacketRef() OVTPacket
	Marshal() []byte
	Unmarshal([]byte) error
}

//type OVTPacket struct {
//	icmp.Message
//	data []byte
//}

type TunnelPacket interface {
	PayloadRef() []byte
}

var (
	OVT_MAGIC = [4]byte{'O', 'V', 'T', 0xAA}
)

const (
	OVT_HEADER_SIZE = 8

	PKG_TOO_SHORT = "Packet too short."
	PKG_INVALID   = "Not a OVTPacket."
)

func PlaceNewOVTPacket(buf []byte, payload_size uint) OVTPacket {
	if uint(len(buf)) < payload_size+OVT_HEADER_SIZE {
		return nil
	}
	copy(buf[0:4], OVT_MAGIC[:])
	return OVTPacket(buf)
}

func OVTPacketUnpack(buf []byte, size_limit uint32) (bool, OVTPacket, error) {

	if len(buf) < 4 {
		return false, nil, errors.New(PKG_TOO_SHORT)
	}
	if bytes.Equal(buf[0:4], OVT_MAGIC[:]) {
		return false, nil, errors.New(PKG_INVALID)
	}
	if len(buf) < 8 {
		return true, nil, errors.New(PKG_TOO_SHORT)
	}
	enc_len := binary.BigEndian.Uint32(buf[4:8])
	if enc_len != uint32(len(buf)) {
		return true, nil, fmt.Errorf("Payload size unmatched. (buffered: %v, encoded: %v)", len(buf), enc_len)
	}
	if enc_len > size_limit {
		return true, nil, fmt.Errorf("Packet size limited for safety.")
	}

	pkt := make(OVTPacket, enc_len)
	copy(pkt.PayloadRef(), buf[OVT_HEADER_SIZE:])
	return true, pkt, nil
}

func (pack OVTPacket) MagicRef() OVTPacket {
	return pack[0:4]
}

func (pack OVTPacket) Pack() []byte {
	var enc_len uint32

	enc_len = uint32(len(pack))

	binary.BigEndian.PutUint32(pack[4:8], enc_len)
	return []byte(pack)
}

func (pack OVTPacket) PayloadRef() []byte {
	return pack[8:]
}
