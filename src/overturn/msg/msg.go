package msg

type MessageHeader interface {
    Major   uint8
    Minor   uint8
    Type    uint8
}

const (
    _ = iota
    HEARTBEAT
    CFG_INFO_REQ
)

type Message interface {
    GetVersion()    *OVTMessageVersion
    Type()          uint8
}

type Heartbeat struct {
    Header      OVTMessageHeader
    net.IP
    CfgIndex    uint64
}

const (
    MAGIC = [4]byte{0x2c, 0xaa, 0xe8, 0x16}
)

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
