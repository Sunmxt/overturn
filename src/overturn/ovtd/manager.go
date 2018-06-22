package ovtd

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"net"
	"overturn/protocol"
	"runtime"
	"strconv"
	"sync/atomic"
)

const (
	CAPTURE_MARK_CHAIN = "OVERTURN_CAPTURE"
	CAPTURE_IPSET      = "overturned"
	IF_NAME_PREFIX     = "ovt"
)

var (
	OUTPUT_RULE        []string = []string{"-m", "comment", "--comment", "Overturn mark traffics", "-j", CAPTURE_MARK_CHAIN}
	ICMP_IGNORE_RULE   []string = []string{"-p", "icmp", "-j", "RETURN"}
	RULE_NOT_MATCH_RET []string = []string{"-m", "set", "!", "--match-set", CAPTURE_IPSET, "dst", "-j", "RETURN"}
)

type NetworkNode struct {
	Active bool
	Name   string
	ID     uuid.UUID
}

type NetworkCluster struct {
	Token             uuid.UUID
	TokenExpireBefore uint64
	TokenExpireAfter  uint64
	Term              uint64
	Index             uint64
	HeartbeatPeriod   uint32
	HeartbeatTimeout  uint32
	ByIP              map[[4]byte]*NetworkNode
	ByID              map[uuid.UUID]*NetworkNode

	Master *NetworkNode
	Self   *NetworkNode
}

type ClusterManager struct {
	Config *NetworkClusterYAML

	Info *NetworkCluster

	Ipt     *iptables.IPTables
	CapIPs  *ipset.IPSet
	IptMark uint32

	NetTun  *ICMPTunnel
	LinkTun *LinkTunnel

	ctl      *Controller
	fd_index uint32
}

func ToIPv4Key(ip net.IP) [4]byte {
	return [4]byte{ip[0], ip[1], ip[2], ip[3]}
}

func NewClusterManager(ctl *Controller, config *NetworkClusterYAML) (*ClusterManager, error) {
	var err error = nil

	nm := new(ClusterManager)
	nm.IptMark = 0x66
	fallback := func(err error, desp string) (*ClusterManager, error) {
		var detail string
		if err != nil {
			detail = err.Error()
		} else {
			detail = ""
		}

		log.WithFields(log.Fields{
			"module":     "ClusterManager",
			"event":      "initialize",
			"err_detail": detail,
		}).Error(desp)
		return nil, err
	}

	nm.Config = config
	nm.ctl = ctl

	if err = nm.prepare(); err != nil {
		return nil, err
	}

	nm.NetTun, err = NewICMPTunnel("0.0.0.0")
	if err != nil {
		return fallback(err, "Cannot listen icmp")
	}
	defer func() {
		if err != nil {
			nm.NetTun.Destroy()
		}
	}()

	// create p2p device
	var net_ns *netlink.Handle
	var li []netlink.Link
	net_ns, err = netlink.NewHandle(netlink.FAMILY_V4)
	if err != nil {
		return fallback(err, "Cannot get control current network namespace.")
	}
	defer net_ns.Delete()

	var link_name string
	tail_num, found := 0, true
	li, err = net_ns.LinkList()
	for ; tail_num < 10 && found; tail_num++ {
		link_name = IF_NAME_PREFIX + strconv.Itoa(tail_num)
		found = false
		for _, link := range li {
			attr := link.Attrs()
			if attr.Name == link_name {
				found = true
				break
			}
		}
	}
	if tail_num >= 10 {
		fallback(nil, "Too many links.")
		return nil, err
	}
	nm.LinkTun, err = NewLinkTunnel(link_name, runtime.NumCPU())
	if err != nil {
		return fallback(err, fmt.Sprintf("Cannot add link %v", link_name))
	}

	if nm.Ipt, err = iptables.New(); err != nil {
		return fallback(err, "Cannot create iptables controller instance.")
	}

	// setup iptables rules
	if err = nm.RefreshRules(); err != nil {
		log.WithFields(log.Fields{
			"module":     "ClusterManager",
			"event":      "configure",
			"err_detail": err.Error(),
		}).Error("Cannot initialize iptables rules.")
		return nil, err
	}

	return nm, nil
}

func (nm *ClusterManager) Start() error {
	var err error = nil

	defer func() {
		if err != nil {
			nm.ClearIPSetRules()
			nm.ClearIptablesRules()
		}
	}()

	if err = nm.LinkTun.Start(); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			nm.LinkTun.Stop()
		}
	}()

	if err = nm.NetTun.Start(); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			nm.LinkTun.Stop()
		}
	}()

	nm.start_handler()
	// Forwarder
	//go nm.cluster_bootstrap()
	//go nm.log_stat()
	return nil
}

func (nm *ClusterManager) PacketRoute(buf []byte) {
	header, err := ipv4.ParseHeader(buf)
	if err != nil {
		log.WithFields(log.Fields{
			"module": "ClusterManager",
			"event":  "packet",
		}).Errorf("Not a valid IP Packet: "+err.Error()+"length: %v", len(buf))
		return
	}

	// ignore all non-ipv4 packet
	if header.Version != 4 {
		return
	}

	node, ok := nm.Info.ByIP[ToIPv4Key(header.Dst.To4())]
	if ok && node != nil {
		tun_pkt := nm.NetTun.NewPacket(uint(len(buf)) + protocol.OVT_HEADER_SIZE)
		ovt_pkt := protocol.PlaceNewOVTPacket(tun_pkt.PayloadRef(), uint(len(buf)), protocol.RAW_PAYLOAD)
		copy(ovt_pkt.PayloadRef(), buf)
		ovt_pkt.Pack()
		nm.NetTun.Write(tun_pkt, &net.IPAddr{header.Dst, ""})
	}
}

func (nm *ClusterManager) DispatchOVTPacket(pkt protocol.OVTPacket) {

	switch pkt.PayloadType() {
	case protocol.RAW_PAYLOAD:
		nm.DeliverPayload(pkt.PayloadRef())
	default:
		break
	}

}

func (nm *ClusterManager) DeliverPayload(payload []byte) {
	fd_index := atomic.AddUint32(&nm.fd_index, 1)
	nm.LinkTun.Write(payload, uint(fd_index))
}

func (nm *ClusterManager) start_handler() {

	nm.NetTun.Handler(func(tun *ICMPTunnel, pkt protocol.TunnelPacket) {
		payload := pkt.PayloadRef()
		is_encap, packet, err := protocol.OVTPacketUnpack(payload, 65536)

		if is_encap {
			if packet == nil {
				if err != nil {
					log.WithFields(log.Fields{
						"module": "ClusterManager",
						"event":  "packet",
					}).Error(err.Error())
				}
			} else {
				nm.DispatchOVTPacket(packet)
			}
		}
	})

	nm.LinkTun.Handler(func(tun *LinkTunnel, data []byte) {
		nm.PacketRoute(data)
	})
}

func (nm *ClusterManager) ClearIPSetRules() {
	nm.CapIPs.Flush()
	nm.CapIPs.Destroy()
	nm.CapIPs = nil
}

func (nm *ClusterManager) ClearIptablesRules() {
	nm.Ipt.ClearChain("mangle", CAPTURE_MARK_CHAIN)
	nm.Ipt.Delete("mangle", "OUTPUT", OUTPUT_RULE...)
	nm.Ipt.DeleteChain("mangle", CAPTURE_MARK_CHAIN)
}

//func (nm *ClusterManager) ClearKernelRoute() {
//    rule := netlink.NewRule()
//    rule.Table = 94
//    rule.Mark = nm.IptMark
//
//    netlink.RuleDel(&rule)
//
//    route := netlink.
//}
//
//func (nm *ClusterManager) RefreshKernelRoute() {
//
//}

func (nm *ClusterManager) Stop() error {
	var err error

	nm.ClearIPSetRules()
	nm.ClearIptablesRules()

	defer func() {
		if err != nil {
			log.WithFields(log.Fields{
				"module": "ClusterManager",
				"event":  "stop",
			}).Error(err.Error())
		}
	}()

	if err = nm.LinkTun.Stop(); err != nil {
		return err
	}
	if err = nm.NetTun.Stop(); err != nil {
		return err
	}

	return nil
}

func (nm *ClusterManager) RefreshRules() error {
	if err := nm.RefreshIPSetRules(); err != nil {
		return err
	}

	if err := nm.RefreshIptablesRules(); err != nil {
		return err
	}

	return nil
}

func (nm *ClusterManager) Destroy() error {
	return nil
}

func (nm *ClusterManager) prepare() error {
	var err error
	var id uuid.UUID
	var ok bool

	nm.Info = new(NetworkCluster)
	nm.Info.Token, err = uuid.Parse(nm.Config.Token)
	if err != nil {
		log.WithFields(log.Fields{
			"module":     "ClusterManager",
			"event":      "initialize",
			"err_detail": err.Error(),
		}).Warning("Invalid join token. Ignore.")
	}
	nm.Info.TokenExpireBefore = nm.Config.TokenExpireBefore
	nm.Info.TokenExpireAfter = nm.Config.TokenExpireAfter
	nm.Info.HeartbeatPeriod = nm.Config.HeartbeatPeriod
	nm.Info.HeartbeatTimeout = nm.Config.HeartbeatTimeout
	nm.Info.Term = nm.Config.Term
	nm.Info.Index = nm.Config.Index

	nm.Info.ByIP = make(map[[4]byte]*NetworkNode)
	nm.Info.ByID = make(map[uuid.UUID]*NetworkNode)

	// load configure
	node_info := new(NetworkNode)
	conflict_ips := make([]net.IP, 0, 10)
	for ID, cfg := range nm.Config.Nodes {

		// parse ID
		node_info.ID, err = uuid.Parse(ID)
		if err != nil {
			log.WithFields(log.Fields{
				"module":     "ClusterManager",
				"event":      "initialize",
				"err_detail": err.Error(),
			}).Errorf("Invalid ID %v for node %v. Ignore.", ID, cfg.Name)
			continue
		}

		nm.Info.ByID[node_info.ID] = node_info
		node_info.Active = cfg.Active
		node_info.Name = cfg.Name

		// Parse IP
		for _, ip_raw := range cfg.Publish {
			ip := net.ParseIP(ip_raw)
			if ip == nil {
				log.WithFields(log.Fields{
					"module":     "ClusterManager",
					"event":      "initialize",
					"err_detail": "",
					"node_id":    ID,
				}).Errorf("Invalid IP Address %v. Ignore.", ip_raw)

				continue
			}
			ip = ip.To4()
			if ip == nil {
				log.WithFields(log.Fields{
					"module":  "ClusterManager",
					"event":   "initialize",
					"node_if": ID,
				}).Errorf("Not a IPv4 Address: %v. Ignore.", ip_raw)

				continue
			}

			if test_node, _ := nm.Info.ByIP[ToIPv4Key(ip.To4())]; test_node != nil {
				log.WithFields(log.Fields{
					"module":     "ClusterManager",
					"event":      "initialize",
					"err_detail": "",
					"node_id":    ID,
				}).Errorf("IP %v Conflict.", ip_raw)

				conflict_ips = append(conflict_ips, ip)
				continue
			}
			nm.Info.ByIP[ToIPv4Key(ip)] = node_info
		}

		node_info = new(NetworkNode)
	}

	// remove conflict ip
	for _, ip := range conflict_ips {
		node_info, ok = nm.Info.ByIP[ToIPv4Key(ip)]
		if ok {
			log.WithFields(log.Fields{
				"module":     "ClusterManager",
				"event":      "initialize",
				"err_detail": "",
				"node_id":    node_info.ID.String(),
			}).Warningf("IP %v removed from %v due to conflict.", ip.String(), node_info.Name)
			delete(nm.Info.ByIP, ToIPv4Key(ip))
		}
	}

	//Find myself
	id = nm.ctl.GetMachineID()
	if existing, ok := nm.Info.ByID[id]; !ok {
		// If not exists
		nm.Info.Self = node_info
		node_info.Active = false
		node_info.Name = "node_" + id.String()[0:8]
		node_info.ID = id
	} else {
		nm.Info.Self = existing
	}
	nm.Info.Master = nil

	return nil
}

func (nm *ClusterManager) RefreshIPSetRules() error {
	var err error = nil

	fallback := func(err error, desp string) error {
		log.WithFields(log.Fields{
			"module":     "ClusterManager",
			"event":      "ipset",
			"err_detail": err.Error(),
		}).Error(desp)
		return err
	}

	if nm.CapIPs == nil {
		nm.CapIPs, err = ipset.New(CAPTURE_IPSET, "hash:ip", &ipset.Params{})
		if err != nil {
			return fallback(err, "Cannot create ipset.")
		}
	}

	if err = nm.CapIPs.Flush(); err != nil {
		return fallback(err, "Cannot flush ipset.")
	}

	for key_ip, _ := range nm.Info.ByIP {
		ip := net.IP(key_ip[:])
		if err = nm.CapIPs.Add(ip.String(), 0); err != nil {
			return fallback(err, fmt.Sprintf("Error occur when add %v", ip.String()))
		}
	}

	return nil
}

func (nm *ClusterManager) RefreshIptablesRules() error {
	var err error = nil
	var ok bool
	fallback := true

	nm.ClearIptablesRules()
	nm.Ipt.NewChain("mangle", CAPTURE_MARK_CHAIN)
	defer func() {
		if fallback {
			nm.Ipt.DeleteChain("mangle", CAPTURE_MARK_CHAIN)
			log.WithFields(log.Fields{
				"module":     "ClusterManager",
				"event":      "iptables",
				"err_detail": err.Error(),
			}).Error("Cannot apply rules.")
		}
	}()

	ok, err = nm.Ipt.Exists("mangle", "OUTPUT", OUTPUT_RULE...)
	if err != nil {
		return err
	}
	if !ok {
		if err = nm.Ipt.Insert("mangle", "OUTPUT", 1, OUTPUT_RULE...); err != nil {
			return err
		}
	}
	defer func() {
		if fallback {
			nm.Ipt.Delete("mangle", "OUTPUT", OUTPUT_RULE...)
		}
	}()

	if err = nm.Ipt.Append("mangle", CAPTURE_MARK_CHAIN, RULE_NOT_MATCH_RET...); err != nil {
		return err
	}
	defer func() {
		if fallback {
			nm.Ipt.ClearChain("mangle", CAPTURE_MARK_CHAIN)
		}
	}()

	if err = nm.Ipt.Append("mangle", CAPTURE_MARK_CHAIN, ICMP_IGNORE_RULE...); err != nil {
		return err
	}

	mark := fmt.Sprintf("0x%x", nm.IptMark)
	if err = nm.Ipt.Append("mangle", CAPTURE_MARK_CHAIN, "-j", "MARK", "--set-mark", mark); err != nil {
		return err
	}

	if err = nm.Ipt.Append("mangle", CAPTURE_MARK_CHAIN, "-j", "RETURN"); err != nil {
		return err
	}

	fallback = false
	return nil
}
