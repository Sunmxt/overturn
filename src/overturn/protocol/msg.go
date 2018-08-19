package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/uuid"
)

const (
	ERR_BUFFER_SMALL = "Buffer is too small."
)

type Message interface {
	Type() uint8
	Marshal() []byte
	Place([]byte) error
	Unmarshal([]byte) error
	Size() uint
}

// Join : Join a network
type JoinRequest struct {
	Name  [16]byte
	Token uuid.UUID
}

func NewJoinRequest(network_name string, token uuid.UUID) *JoinRequest {
	m := new(JoinRequest)
	copy(m.Name[:], network_name)
	m.Token = token
	return m
}

func (m *JoinRequest) Type() uint8 {
	return JOIN_REQUEST
}

func (m *JoinRequest) Marshal() []byte {
	buf := make([]byte, 16+16)
	m.Place(buf)
	return buf
}

func (m *JoinRequest) Place(buf []byte) error {
	if uint(len(buf)) < m.Size() {
		return errors.New(ERR_BUFFER_SMALL)
	}
	copy(buf[0:16], m.Name[:])
	copy(buf[16:32], m.Token[:])
    return nil
}

func (m *JoinRequest) Unmarshal(buf []byte) error {
	if uint(len(buf)) != m.Size() {
		return fmt.Errorf("Not a valid JoinRequest message. (buffered: %v)", len(buf))
	}
	copy(m.Name[:], buf[0:16])
	copy(m.Token[:], buf[16:32])
	return nil
}

func (m *JoinRequest) Size() uint {
	return uint(16 + 16)
}

// NodeActivate : An existing node is up.
type NodeActivate struct {
	ID uuid.UUID
}

func NewNodeActivateMessage(id uuid.UUID) *NodeActivate {
	return &NodeActivate{
		ID: id,
	}
}

func (m *NodeActivate) Size() uint {
	return uint(binary.Size(m.ID))
}

func (m *NodeActivate) Type() uint8 {
	return NODE_ACTIVATE
}

func (m *NodeActivate) Marshal() []byte {
	buf := make([]byte, m.Size())
	m.Place(buf)
	return buf
}

func (m *NodeActivate) Place(buf []byte) error {
	if uint(len(buf)) < m.Size() {
		return errors.New(ERR_BUFFER_SMALL)
	}
	copy(buf[0:binary.Size(m.ID)], m.ID[:])
	return nil
}

func (m *NodeActivate) Unmarshal(buf []byte) error {
	if uint(len(buf)) < m.Size() {
		return fmt.Errorf("Not a valid NodeActivate message.")
	}
	copy(m.ID[:], buf[0:binary.Size(m.ID)])
	return nil
}

// Heartbeat : Liveness pulse signal.
// Subtype: Master Heartbeat, Node Heartbeat
type Heartbeat struct {
	NetName [16]byte
	Master  uuid.UUID
	Term    uint64
	Index   uint64
}

func NewHeartbeat() *Heartbeat {
	m := new(Heartbeat)
	return m
}

func (m *Heartbeat) Type() uint8 {
	return NODE_ACTIVATE
}

func (m *Heartbeat) Marshal() []byte {
	buf := make([]byte, m.Size())
	m.Place(buf)
	return buf
}

func (m *Heartbeat) Place(buf []byte) error {
	if uint(len(buf)) < m.Size() {
		return errors.New(ERR_BUFFER_SMALL)
	}
	copy(buf[0:16], m.NetName[:])
	copy(buf[16:32], m.Master[:])
	binary.BigEndian.PutUint64(buf[32:40], m.Term)
	binary.BigEndian.PutUint64(buf[40:48], m.Index)
	return nil
}

func (m *Heartbeat) Unmarshal(buf []byte) error {
	if uint(len(buf)) < m.Size() {
		return fmt.Errorf("Not a valid Heartbeat message.")
	}
	copy(m.NetName[:], buf[0:16])
	copy(m.Master[:], buf[16:32])
	m.Term = binary.BigEndian.Uint64(buf[32:40])
	m.Index = binary.BigEndian.Uint64(buf[40:48])
	return nil
}

func (m *Heartbeat) Size() uint {
	return uint(binary.Size(*m))
}
