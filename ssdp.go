package disgo

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
)

// SSDP

const (
	ssdp4Address = "239.255.255.250"
	ssdp6Address = "ff0e::c"
	ssdpPort     = 1900
	// SSDPProtocolName name of the multicast protocol.
	SSDPProtocolName = "SSDP"
)

var (
	ssdp4UDPAddress = net.UDPAddr{IP: net.ParseIP(ssdp4Address), Port: ssdpPort}
	ssdp6UDPAddress = net.UDPAddr{IP: net.ParseIP(ssdp6Address), Port: ssdpPort}
)

func ssdpLogError(err error) {
	fmt.Fprintf(os.Stderr, "[error]: %s: %s\n", SSDPProtocolName, err)
}

// Send an M-SEARCH packet on an UDP connection to a UDP destination address
func ssdpQuery(conn *net.UDPConn, dst *net.UDPAddr) {

	// Build SSDP request

	ssdpMsearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST:" + dst.String() + "\r\n" +
		"MAN:\"ssdp:discover\"\r\n" +
		"ST: ssdp:all\r\n" +
		"MX: 1\r\n\r\n"

	// Send

	_, err := conn.WriteToUDP([]byte(ssdpMsearch), dst)
	if err != nil {
		ssdpLogError(err)
		return
	}
}

// Send an M-SEARCH packet on an UDP connection to a UDP destination address
func ssdpListen(conn *net.UDPConn, reporter Reporter) {
	buffer := make([]byte, 1024)

	for {
		// Read

		size, src, err := conn.ReadFromUDP(buffer)
		if err != nil {
			ssdpLogError(err)
			return
		}

		var server string
		reader := bufio.NewReader(bytes.NewReader(buffer[:size]))
		req := &http.Request{} // Needed for ReadResponse but doesn't have to be real
		rsp, err := http.ReadResponse(reader, req)
		if err != nil {
			server = "[parser error]"
		} else {
			server = rsp.Header["Server"][0]
		}

		// Output

		reporter.Print(src.IP, server)
	}
}

// SSDPScan queries and listens for SSDP multicast on all interfaces.
func SSDPScan(ifSockAddr net.UDPAddr, reporter Reporter) {

	var multicastAddr net.UDPAddr
	if ifSockAddr.IP.To4() != nil {
		multicastAddr = ssdp4UDPAddress
	} else {
		multicastAddr = ssdp6UDPAddress
	}

	ifAddrConn, err := net.ListenUDP("udp", &ifSockAddr)
	if err != nil {
		ssdpLogError(err)
		return
	}

	ssdpQuery(ifAddrConn, &multicastAddr)
	ssdpListen(ifAddrConn, reporter)
}
