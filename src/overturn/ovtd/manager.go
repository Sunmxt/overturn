package ovtd

import (
    "golang.org/x/net/icmp"

    "fmt"
    "github.com/coreos/go-iptables/iptables"
    "github.com/janeczku/go-ipset/ipset"
    log "github.com/sirupsen/logrus"
    "github.com/google/uuid"
    "overturn/msg"
    "overturn/tunnel"
    "github.com/vishvananda/netlink"
)

const (
    CAPTURE_MARK_CHAIN  = "OVERTURN_CAPTURE"
    CAPTURE_IPSET       = "overturned"
    IF_NAME_PREFIX      = "ovt"
)

type NetNode struct {
    IPs             []net.IPAddr
    UUID            uuid.UUID
}

type NetManager struct {
    Ipt             *iptables.IPTables
    CapIPs          *ipset.IPSet

    ICMPConn        *icmp.PacketConn

    TunName         string
    Node            []*NetNode
    Self            *NetNode
    IptMark         uint32
}


func NewNetManager(opts *Options) *NetManager, error {
    var err error = nil

    nm := new(NetManager)

    nm.ICMPConn, err = ListenPacket("ip4:icmp", "0.0.0.0")
    if err != nil {
        log.WithFields(log.Fields{
                "module" : "NetManager",
                "event" : "initialize"
                "err_detail" : err.Error()
            }).Error("Cannot listen icmp.")
        return nil, err
    }
    defer func() {
        if err != nil {
            nm.ICMPConn.Close()
        }
    }

    
    if nm.Ipt, err = iptables.New(); err != nil {
        log.WithFields(log.Fields{
                "module" : "NetManager",
                "event" : "initialize"
                "err_detail" : err.Error()
            }).Error("Cannot create iptables controller instance.")
        return nil, err
    }

    // create tunnel interface
    var net_ns *netlink.Handle
    net_ns, err = netlink.NewHandle(netlink.FAMILY_V4)
    if err != nil {
        log.WithFields(log.Fields{
                "module" : "NetManager",
                "event" : "initialize"
                "err_detail" : err.Error()
            }).Error("Cannot get control current network namespace.")
        return nil, err
    }
    defer net_ns.Delete()

    nm.TunName = "ovt"

    // setup iptables rules
    if err = nm.RefreshRules(); err != nil {
        log.WithFields(log.Fields{
                "module" : "NetManager",
                "event" : "configure"
                "err_detail" : err.Error()
            }).Error("Cannot initialize iptables rules.")
        return nil, err
    }

    return nm
}


func (nm *NetManager) Run() {

     
}

func (nm *NetManager) RefrushRules error {
    if err := nm.RefreshIPSetRules(); err != nil {
        return err
    }

    if err := nm.RefreshIptablesRules(); err != nil {
        return err
    }

    return err
}


func (nm *NetManager) RefreshIPSetRules() error {
    var err error = nil

    fallback := func(err error, desp string) {
        log.WithFields(log.Fields{
                "module" : "NetManager"
                "event" : "ipset"
                "err_detail" : "err"
            }).Error(desp)
        return err
    }

    if nm.CapIPs == nil {
        nm.CapIPs, err = ipset.New(CAPTURE_IPSET, "hash:ip", &ipset.Params{})
        if err != nil {
            return fallback(err, "Cannot create ipset.")
        }
    }

    if err = nm.CapIPs.Flush(); err != nil{
        return fallback(err, "Cannot flush ipset.")
    }

    for idx, node := range nm.Node {
        for i, ip := range node.IPs {
            if err = nm.CapIPs.Add(ip.String(), 0); err != nil {
                return fallback(err, fmt.Sprintf("Error occur when add %v", ip.String()))
            }
        }
    }

    return nil
}


func (nm *NetManager) RefreshIptablesRules() error {
    var err error = nil
    var err_detail string
    fallback := true

    nm.Ipt.NewChains("mangle", CAPTURE_MARK_CHAIN)
    nm.Ipt.ClearChain("mangle", CAPTURE_MARK_CHAIN)
    defer func() {
        if fallback {
            nm.Ipt.DeleteChain("mangle", CAPTURE_MARK_CHAIN)
            log.WithFields(log.Fields{
                    "module" : "NetManager",
                    "event" : "iptables",
                    "err_detail" : err.Error()
                }).Error("Cannot apply rules.")
        }
    }
    
    const OUTPUT_RULE = []string{"m", "comment", "--comment", "Overturn mark traffics", "-j" , CAPTURE_MARK_CHAIN}
    if !nm.Ipt.Exists("mangle", "OUTPUT", OUTPUT_RULE...) {
        if err = nm.Ipt.Insert("mangle", "OUTPUT", 1, OUTPUT_RULE...); err != nil {
            err_detail = "-t mangle -A OUTPUT " + strings.Join(OUTPUT_RULE, " ")
            return err
        }
    }
    defer func() {
        if fallback {
            nm.Ipt.Delete("mangle", "OUTPUT", OUTPUT_RULE...)
        }
    }

    const RULE_NOT_MATCH_RET = []string{"!", "-m", "set", "--match-set", CAPTURE_IPSET, "dst", "-j", "RETURN"}
    if err = nm.Ipt.Append("mangle", CAPTURE_MARK_CHAIN, RULE_NOT_MATCH_RET...); err != nil {
        err_detail = "-t mangle -A " + CAPTURE_MARK_CHAIN + strings.Join(RULE_NOT_MATCH_RET, " ")
        return err 
    }
    defer func() {
        if fallback {
            nm.Ipt.ClearChain("mangle", CAPTURE_MARK_CHAIN)
        }
    }

    mark := fmt.Sprintf("0x%x", nm.IptMark)
    if err = nm.Ipt.Append("mangle", CAPTURE_MARK_CHAIN, "-j", "MARK", "--set-mark", mark); err != nil {
        err_detail = "-t mangle -A " + CAPTURE_MARK_CHAIN + "-j MARK --set-mark " + mark
        return err
    }

    if err = nm.Ipt.Append("mangle", CAPTURE_MARK_CHAIN, "-j", "RETURN"); err != nil {
        err_detail = "-t mangle -A " + CAPTURE_MARK_CHAIN + "-j RETURN"
        return err
    }

    fallback = false
    return nil
}


func (nm *NetManager) ReceiveLowLevelMessage() *msg.Message {
    
}

func (nm *NetManager) SendLowLevelMessage(message *msg.Message) {

} 
