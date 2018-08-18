package msg

import (
	"encoding/binary"
	"fmt"
	"github.com/google/uuid"
)

type MessageHeader struct {
	Major uint8
	Minor uint8
	Type  uint8
}

const MSG_HEADER_SIZE = 3

func (m *MessageHeader) Marshal(buf []byte) {
	buf[0] = m.Major
	buf[1] = m.Minor
	buf[2] = m.Type
}

func (m *MessageHeader) Unmarshal(buf []byte) error {
	m.Major = buf[0]
	m.Minor = buf[1]
	m.Type = buf[2]
}

const (
	NODE_ACTIVATE = iota
	HEARTBEAT_MASTER
	HEARTBEAT_NODE
    JOIN_REQUEST
)

const (
	VERSION_MAJOR = 1
	VERSION_MINOR = 0
)

type Message interface {
	GetVersion() (uint8, uint8)
	Type() uint8
	Marshal() []byte
	Unmarshal([]byte) error
	Size() uint
}

// Join : Join a network
type JoinRequest struct {
    Header MessageHeader
    Name   [16]byte
    Token  uuid.UUID
}

func NewJoinRequest(network_name string, token uuid.UUID) *JoinRequest {
    m := new(JoinRequest)
    m.Header.Major = VERSION_MAJOR
    m.Header.Major = VERSION_MINOR
    m.Header.Type = JOIN_REQUEST
    copy(m.Name[:], network_name)
    m.Token = token
    return m
}

func (m *JoinRequest) GetVersion() (uint8, uint8) {
    return m.Header.Major, m.Header.Minor
}

func (m *JoinRequest) Type() uint8 {
    return m.Header.Type
}

func (m *JoinRequest) Marshal() []byte {
    buf := make([]byte, len(*m))
    m.Header.Marshal(buf[0:3])
    copy(buf[3:19], m.Name)
    copy(buf[19:35], m.Token)
    return buf
}

func (m *JoinRequest) Unmarshal(buf []byte) error {
    var err error
    if len(buf) != len(*m) {
        return fmt.Errorf("Not a valid JoinRequest message.")
    }
    err = m.Header.Unmarshal(buf[0:3])
    if err != nil {
        return err
    }
    copy(m.Name, buf[3:19])
    copy(m.Token, buf[19:35])
    return nil
}

func (m *JoinRequest) Size() uint {
    return uint(len(*m))
}

// NodeActivate : An existing node is up.
type NodeActivate struct {
	Header MessageHeader
	ID     *uuid.UUID
}

func NewNodeActivateMessage(id *uuid.UUID) *NodeActivate {
	return &NodeActivate{
		Header: MessageHeader{
			Major: VERSION_MAJOR,
			Minor: VERSION_MINOR,
			Type:  NODE_ACTIVATE,
		},
		ID: id,
	}
}

func (m *NodeActivate) GetVersion() (uint8, uint8) {
	return m.Header.Major, m.Header.Minor
}

func (m *NodeActivate) Size() uint {
	return uint(MSG_HEADER_SIZE + binary.Size(m.ID))
}

func (m *NodeActivate) Type() uint8 {
	return m.Header.Type
}

func (m *NodeActivate) Marshal() []byte {
	buf := make([]byte, m.Size(), m.Size())
	m.Header.Marshal(buf[0:3])
	copy(buf[3:3+binary.Size(m.ID)], m.ID[:])
	return buf
}

func (m *NodeActivate) Unmarshal(buf []byte) error {
	if uint(len(buf)) < m.Size() || uint8(buf[2]) != NODE_ACTIVATE {
		return fmt.Errorf("Not a valid NodeActivate message.")
	}
	if m.ID == nil {
		return fmt.Errorf("Null ID Buffer.")
	}
	m.Header.Unmarshal(buf[0:3])
	copy(m.ID[:], buf[3:3+binary.Size(m.ID)])
	return nil
}

// Heartbeat : Liveness pulse signal.
// Subtype: Master Heartbeat, Node Heartbeat
type Heartbeat struct {
	Header  MessageHeader
	NetName [16]byte
    Master  uuid.UUID
	Term    uint64
	Index   uint64
}

func NewMasterHeartbeat() *Heartbeat {
	m := new(Heartbeat)
	m.Header.Major = VERSION_MAJOR
	m.Header.Minor = VERSION_MINOR
	m.Header.Type = HEARTBEAT_MASTER
	return m
}

func NewNodeHeartbeat() *Heartbeat {
    m := new(Heartbeat)
    m.Header.Major = VERSION_MAJOR
    m.Header.Minor = VERSION_MINOR
    m.Header.Type = HEARTBEAT_NODE
    return m
}

func (m *Heartbeat) GetVersion() (uint8, uint8) {
	return m.Header.Major, m.Header.Minor
}

func (m *Heartbeat) Type() uint8 {
	return m.Header.Type
}

func (m *Heartbeat) Marshal() []byte {
	buf := make([]byte, m.Size(), m.Size())
	m.Header.Marshal(buf[0:3])
	copy(buf[3:19], m.NetName[:])
    copy(buf[19:35], m.Master[:]])
	binary.BigEndian.PutUint64(buf[35:43], m.Term)
	binary.BigEndian.PutUint64(buf[43:51], m.Index)
	return buf
}

func (m *Heartbeat) Unmarshal(buf []byte) error {
	if uint(len(buf)) < m.Size() || (uint8(buf[2]) != HEARTBEAT_MASTER && uint8(buf[2]) != HEARTBEAT_NODE) {
		return fmt.Errorf("Not a valid Heartbeat message.")
	}
	m.Header.Unmarshal(buf[0:3])
	copy(m.NetName[:], buf[3:19])
    copy(m.Master[:], buf[19:35])
	m.Term = binary.BigEndian.Uint64(buf[35:43])
	m.Index = binary.BigEndian.Uint64(buf[43:51])
	return nil
}

func (m *Heartbeat) Size() uint {
	return uint(binary.Size(*m))
}

//
type ConfigInfoRequest struct {
	Header   MessageHeader
	CfgIndex uint64
	Term     uint64
}

type ConfigResponse struct {
	Header MessageHeader
}
