package ovtd

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/vishvananda/netlink"
	"net"
	"overturn/msg"
	"runtime"
	"strconv"
	"strings"
)

const (
	CAPTURE_MARK_CHAIN = "OVERTURN_CAPTURE"
	CAPTURE_IPSET      = "overturned"
	IF_NAME_PREFIX     = "ovt"
)

type NetworkNode struct {
	Active bool
	Name   string
	ID     uuid.UUID
}

type ConfigOperation struct {
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

	ctl *Controller
}

func ToIPv4Key(ip net.IP) [4]byte {
	return [4]byte{ip[0], ip[1], ip[2], ip[3]}
}

func NewClusterManager(ctl *Controller, config *NetworkClusterYAML) (*ClusterManager, error) {
	var err error = nil

	nm := new(ClusterManager)
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

func (nm *ClusterManager) Start() {

}

func (nm *ClusterManager) Stop() {
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

			if test_node, _ := nm.Info.ByIP[ToIPv4Key(ip)]; test_node != nil {
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
	var err_detail string
	var ok bool
	fallback := true

	nm.Ipt.NewChain("mangle", CAPTURE_MARK_CHAIN)
	nm.Ipt.ClearChain("mangle", CAPTURE_MARK_CHAIN)
	defer func() {
		if fallback {
			nm.Ipt.DeleteChain("mangle", CAPTURE_MARK_CHAIN)
			log.WithFields(log.Fields{
				"module":     "ClusterManager",
				"event":      "iptables",
				"err_detail": err.Error() + ":" + err_detail,
			}).Error("Cannot apply rules.")
		}
	}()

	OUTPUT_RULE := []string{"m", "comment", "--comment", "Overturn mark traffics", "-j", CAPTURE_MARK_CHAIN}
	ok, err = nm.Ipt.Exists("mangle", "OUTPUT", OUTPUT_RULE...)
	if err != nil {
		return err
	}
	if !ok {
		if err = nm.Ipt.Insert("mangle", "OUTPUT", 1, OUTPUT_RULE...); err != nil {
			err_detail = "-t mangle -A OUTPUT " + strings.Join(OUTPUT_RULE, " ")
			return err
		}
	}
	defer func() {
		if fallback {
			nm.Ipt.Delete("mangle", "OUTPUT", OUTPUT_RULE...)
		}
	}()

	RULE_NOT_MATCH_RET := []string{"!", "-m", "set", "--match-set", CAPTURE_IPSET, "dst", "-j", "RETURN"}
	if err = nm.Ipt.Append("mangle", CAPTURE_MARK_CHAIN, RULE_NOT_MATCH_RET...); err != nil {
		err_detail = "-t mangle -A " + CAPTURE_MARK_CHAIN + strings.Join(RULE_NOT_MATCH_RET, " ")
		return err
	}
	defer func() {
		if fallback {
			nm.Ipt.ClearChain("mangle", CAPTURE_MARK_CHAIN)
		}
	}()

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

func (nm *ClusterManager) ReceiveLowLevelMessage() *msg.Message {
	return nil
}

func (nm *ClusterManager) SendLowLevelMessage(message *msg.Message) {
}
