package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Packet Encapsulation
type OVTPacket []byte

// +-----------------+
// |    magic (+0)   |
// |   = 'OVT\xAA'   |
// +--------+--------+
// | Version|  Type  |
// |  (+4)  |  (+6)  |
// +--------+--------+
// |   Length (+8)   |
// +-----------------+
// |  Payload (+12)  |
// +-----------------+

type OVTEncapsulatedPacket interface {
	OVTPacketRef() OVTPacket
	Marshal() []byte
	Unmarshal([]byte) error
}

type TunnelPacket interface {
	PayloadRef() []byte
}

var (
	OVT_VERSION = 0xAA
	OVT_MAGIC   = [4]byte{'O', 'V', 'T', 0xAA}
	VERSION     = [2]byte{1, 0}
)

const (
	OVT_HEADER_SIZE = 12

	PKG_TOO_SHORT = "Packet too short."
	PKG_INVALID   = "Not a OVTPacket."
)

const (
	RAW_PAYLOAD = iota
	NODE_ACTIVATE
	HEARTBEAT_MASTER
	HEARTBEAT_NODE
	JOIN_REQUEST
)

func PlaceNewOVTPacket(buf []byte, payload_size uint, packet_type uint16) OVTPacket {
	if uint(len(buf)) < payload_size+OVT_HEADER_SIZE {
		return nil
	}
	copy(buf[0:4], OVT_MAGIC[:])
	copy(buf[4:6], VERSION[:])
	binary.BigEndian.PutUint16(buf[6:8], packet_type)
	return OVTPacket(buf)
}

func OVTPacketUnpack(buf []byte, size_limit uint32) (bool, OVTPacket, error) {

	if len(buf) < OVT_HEADER_SIZE {
		return false, nil, errors.New(PKG_TOO_SHORT)
	}
	if !bytes.Equal(buf[0:4], OVT_MAGIC[:]) {
		return false, nil, errors.New(PKG_INVALID)
	}
	if len(buf) < OVT_HEADER_SIZE {
		return true, nil, errors.New(PKG_TOO_SHORT)
	}
	enc_len := binary.BigEndian.Uint32(buf[8:12])
	if enc_len != uint32(len(buf)) {
		return true, nil, fmt.Errorf("Packet size unmatched. (buffered: %v, encoded: %v)", len(buf), enc_len)
	}
	if enc_len > size_limit {
		return true, nil, fmt.Errorf("Packet size limited for safety.")
	}
	return true, OVTPacket(buf), nil
}

func (pack OVTPacket) PayloadType() uint16 {
	return binary.BigEndian.Uint16(pack[6:8])
}

func (pack OVTPacket) MagicRef() OVTPacket {
	return pack[0:4]
}

func (pack OVTPacket) Version() (uint8, uint8) {
	return pack[4], pack[5]
}

func (pack OVTPacket) Pack() []byte {
	var enc_len uint32

	enc_len = uint32(len(pack))

	binary.BigEndian.PutUint32(pack[8:12], enc_len)
	return []byte(pack)
}

func (pack OVTPacket) PayloadRef() []byte {
	return pack[OVT_HEADER_SIZE:]
}
