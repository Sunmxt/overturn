package ovtd

import (
    "net"
)

type ICMPTunnelWorker struct {
     
}

func NewICMPTunnelWorker() {
    net.ListenPacket("ip4:icmp", "0.0.0.0")
}
