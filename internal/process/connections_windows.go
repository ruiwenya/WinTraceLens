//go:build windows

package process

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

const (
	afInet                  = 2
	afInet6                 = 23
	tcpTableOwnerPIDAll     = 5
	udpTableOwnerPID        = 1
	errorInsufficientBuffer = 122
)

var (
	modIphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

func CollectConnections() ([]ConnectionInfo, error) {
	collectors := []struct {
		name string
		fn   func() ([]ConnectionInfo, error)
	}{
		{name: "tcp4", fn: tcp4Connections},
		{name: "tcp6", fn: tcp6Connections},
		{name: "udp4", fn: udp4Connections},
		{name: "udp6", fn: udp6Connections},
	}

	var items []ConnectionInfo
	var errs []string
	for _, collector := range collectors {
		rows, err := collector.fn()
		if err != nil {
			errs = append(errs, collector.name+": "+err.Error())
			continue
		}
		items = append(items, rows...)
	}
	if len(items) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "; "))
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].PID == items[j].PID {
			if items[i].Protocol == items[j].Protocol {
				return items[i].Local < items[j].Local
			}
			return items[i].Protocol < items[j].Protocol
		}
		return items[i].PID < items[j].PID
	})
	return items, nil
}

func Connections(pid uint32) ([]ConnectionInfo, error) {
	items, err := CollectConnections()
	if err != nil {
		return nil, err
	}

	filtered := make([]ConnectionInfo, 0)
	for _, item := range items {
		if item.PID == pid {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func tcp4Connections() ([]ConnectionInfo, error) {
	buf, err := extendedTable(procGetExtendedTcpTable, tcpTableOwnerPIDAll, afInet)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[4]))
	items := make([]ConnectionInfo, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		items = append(items, newConnectionInfo(row.OwningPID, "TCP4", ipv4(row.LocalAddr), networkPort(row.LocalPort), ipv4(row.RemoteAddr), networkPort(row.RemotePort), tcpState(row.State)))
	}
	return items, nil
}

func tcp6Connections() ([]ConnectionInfo, error) {
	buf, err := extendedTable(procGetExtendedTcpTable, tcpTableOwnerPIDAll, afInet6)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCP6RowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[4]))
	items := make([]ConnectionInfo, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		items = append(items, newConnectionInfo(row.OwningPID, "TCP6", ipv6(row.LocalAddr, row.LocalScopeID), networkPort(row.LocalPort), ipv6(row.RemoteAddr, row.RemoteScopeID), networkPort(row.RemotePort), tcpState(row.State)))
	}
	return items, nil
}

func udp4Connections() ([]ConnectionInfo, error) {
	buf, err := extendedTable(procGetExtendedUdpTable, udpTableOwnerPID, afInet)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibUDPRowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[4]))
	items := make([]ConnectionInfo, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibUDPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		items = append(items, newConnectionInfo(row.OwningPID, "UDP4", ipv4(row.LocalAddr), networkPort(row.LocalPort), "", 0, ""))
	}
	return items, nil
}

func udp6Connections() ([]ConnectionInfo, error) {
	buf, err := extendedTable(procGetExtendedUdpTable, udpTableOwnerPID, afInet6)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibUDP6RowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[4]))
	items := make([]ConnectionInfo, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibUDP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		items = append(items, newConnectionInfo(row.OwningPID, "UDP6", ipv6(row.LocalAddr, row.LocalScopeID), networkPort(row.LocalPort), "", 0, ""))
	}
	return items, nil
}

func extendedTable(proc *syscall.LazyProc, tableClass uint32, addressFamily uintptr) ([]byte, error) {
	var size uint32
	ret, _, err := proc.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		addressFamily,
		uintptr(tableClass),
		0,
	)
	if ret != errorInsufficientBuffer && ret != 0 {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	ret, _, err = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		addressFamily,
		uintptr(tableClass),
		0,
	)
	if ret != 0 {
		return nil, err
	}
	return buf, nil
}

func endpoint4(addr uint32, port uint32) string {
	return fmt.Sprintf("%s:%d", ipv4(addr), networkPort(port))
}

func endpoint6(addr [16]byte, scope uint32, port uint32) string {
	ip := net.IP(addr[:]).String()
	if scope != 0 {
		ip = fmt.Sprintf("%s%%%d", ip, scope)
	}
	return fmt.Sprintf("[%s]:%d", ip, networkPort(port))
}

func ipv4(addr uint32) string {
	return net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24)).String()
}

func ipv6(addr [16]byte, scope uint32) string {
	ip := net.IP(addr[:]).String()
	if scope != 0 {
		ip = fmt.Sprintf("%s%%%d", ip, scope)
	}
	return ip
}

func newConnectionInfo(pid uint32, protocol, localIP string, localPort uint16, remoteIP string, remotePort uint16, state string) ConnectionInfo {
	return ConnectionInfo{
		PID:        pid,
		Protocol:   protocol,
		Local:      formatEndpoint(localIP, localPort),
		LocalIP:    localIP,
		LocalPort:  localPort,
		Remote:     formatEndpoint(remoteIP, remotePort),
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		RemoteKind: remoteKind(remoteIP),
		State:      state,
	}
}

func formatEndpoint(ip string, port uint16) string {
	if strings.TrimSpace(ip) == "" {
		return ""
	}
	host := ip
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == 0 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func remoteKind(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	scope := ""
	if idx := strings.LastIndex(value, "%"); idx >= 0 {
		scope = value[idx+1:]
		value = value[:idx]
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	if ip.IsUnspecified() {
		return "未连接"
	}
	if ip.IsLoopback() {
		return "本机"
	}
	if ip.IsPrivate() {
		return "内网"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || scope != "" {
		return "链路本地"
	}
	if ip.IsMulticast() {
		return "组播"
	}
	if ip.Equal(net.IPv4(255, 255, 255, 255)) {
		return "广播"
	}
	return "公网/外部"
}

func networkPort(port uint32) uint16 {
	return uint16((port&0xff)<<8 | (port&0xff00)>>8)
}

func tcpState(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN-SENT"
	case 4:
		return "SYN-RECEIVED"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN-WAIT-1"
	case 7:
		return "FIN-WAIT-2"
	case 8:
		return "CLOSE-WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST-ACK"
	case 11:
		return "TIME-WAIT"
	case 12:
		return "DELETE-TCB"
	default:
		return fmt.Sprintf("STATE-%d", state)
	}
}
