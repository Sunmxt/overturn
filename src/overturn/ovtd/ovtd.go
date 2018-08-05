package ovtd



type Node struct {
    SelfIPs         []net.IPAddr

    CfgIndex        uint64
    Term            uint64
    UUID            
}

type Options struct {
    Config          string
    DynamicConfig   string
}

type Manager struct {
    Self        *Node
    Endpoints   map[net.IP] 
}


func Main() {
    opts := parse_args()
    if opts == nil {
        return
    }

    nm, err := NewNetManager(opts) 
    if err != nil {
        return
    }

    nm.Run()
}
