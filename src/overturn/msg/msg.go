package msg

import (
    "github.com/google/uuid"
    "encoding/binary"
    "fmt"
)

type MessageHeader interface {
    Major   uint8
    Minor   uint8
    Type    uint8
}

const MSG_HEADER_SIZE = 3

func (m *MessageHeader) Marshal(buf []byte) {
    buf[0] = byte(m.Major)
    buf[1] = byte(m.Minor)
    buf[2] = byte(m.Type)
}

const (
    NODE_ACTIVATE       = iota
    HEARTBEAT_MASTER
    HEARTBEAT_NODE
)

const (
    VERSION_MAJOR   = 1
    VERSION_MINOR   = 0
)

type Message interface {
    GetVersion() uint8, uint8
    Type() uint8
    Marshal() []byte
    Unmarshal([]byte) error
    Size() uint
}


// NodeActivate : An existing node is up.
type NodeActivate struct {
    Header          OVTMessageHeader
    ID              *uuid.UUID
}

func NewNodeActivateMessage(id *uuid.UUID) *NodeActivate {
    return &NodeActivate{
            Header : OVTMessageHeader {
                    Major: VERSION_MAJOR,
                    Minor: VERSION_MINOR,
                    Type: NODE_ACTIVATE,
                }, 
            ID: id
        }
}

func (m *NodeActivate) GetVersion() uint8, uint8 {
    return m.Header.Major, m.Header.Minor
}

func (m *NodeActivate) Size() uint {
    return MSG_HEADER_SIZE + binary.Size(m.ID)
}

func (m *NodeActivate) Type() uint8 {
    return m.Header.Type
}

func (m *NodeActivate) Marshal() []byte {
    buf := make([]byte, m.Size(), m.Size()) 
    m.Header.Marshal(buf[0:3])
    copy(buf[3: 3 + binary.Size(m.ID)], *m.ID)
    return buf
}

func (m *NodeActivate) Unmarshal(buf []byte) error {
    if len(buf) < m.Size() || uint8(buf[2]) != NODE_ACTIVATE {
        return fmt.Errorf("Not a valid NodeActivate message.")
    }
    if m.ID == nil {
        return fmt.Errorf("Null ID Buffer.")
    }
    m.Header.Unmarshal(buf[0:3])
    copy(*m.ID, buf[3: 3 + binary.Size(m.ID)])
    return nil
}


// Heartbeat : Liveness pulse signal.
// Subtype: Master Heartbeat, Node Heartbeat
type Heartbeat struct {
    Header          OVTMessageHeader
    NetName         [16]byte
    Term            uint64
    Index           uint64
}

func NewHeartbeat(heartbeat_type uint8) *Heartbeat {
    m := new(Heartbeat)
    m.Header.Major = VERSION_MAJOR
    m.Header.Minor = VERSION_MINOR
    m.Header.Type = heartbeat_type
    return m    
}

func (m *Heartbeat) GetVersion() uint8, uint8 {
    return m.Header.Major, m.Header.Minor
}

func (m *Heartbeat) Type() uint8 {
    return m.Header.Type
}

func (m *Heartbeat) Marshal() []byte {
    buf := make([]byte, m.Size(), m.Size())
    m.Header.Marshal(buf[0:3])
    copy(buf[3: 19], m.NetName)
    binary.PutUvarint(buf[19: 27], m.Term)
    binary.PutUvarint(buf[27: 35], m.Index)
    return buf
}

func (m *Heartbeat) Unmarshal(buf []byte) error {
    if len(buf) < m.Size() || (uint8(buf[2]) != HEARTBEAT_MASTER && uint8(buf[2]) != HEARTBEAT_NODE){
        return fmt.Errorf("Not a valid Heartbeat message.")
    }
    m.Header.Unmarshal(buf[0:3])
    copy(m.NetName, buf[3:19])
    m.Term = binary.Uvarint(buf[19: 27])
    m.Index = binary.Uvarint(buf[27: 35])
    return nil
}

func (m *Heartbeat) Size() uint {
    return binary.Size(*m)
}

type TunnelPayload struct {
    Magic   [4]byte
    Header  OVTMessageHeader
    
}

type ConfigInfoRequest struct {
    Header      OVTMessageHeader
    CfgIndex    uint64
    Term        uint64
}

type ConfigResponse struct {
    Header      OVTMessageHeader
    CfgIndex    u
}
