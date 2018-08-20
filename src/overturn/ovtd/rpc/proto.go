package rpc

// Version
const (
	RPC_VERSION_MAJOR = 1
	RPC_VERSION_MINOR = 0
)

var (
	RPC_MAGIC = [4]byte{'O', 'V', 'T', 'D'}
)

type VersionArgs struct {
	Magic [4]byte
	Major uint8
	Minor uint8
}

type VersionResult struct {
	Magic [4]byte
	Major uint8
	Minor uint8
}

type StopDaemonArgs struct{}

type StopDaemonResult struct {
	ExitCode int
}
