package ssdp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/steabert/disgo/reporter"
)

// SSDP

const (
	ssdp4Address = "239.255.255.250"
	ssdp6Address = "ff0e::c"
	ssdpPort     = 1900
	protocol     = "SSDP"
)

var (
	ssdp4UDPAddress = net.UDPAddr{IP: net.ParseIP(ssdp4Address), Port: ssdpPort}
	ssdp6UDPAddress = net.UDPAddr{IP: net.ParseIP(ssdp6Address), Port: ssdpPort}
)

func logError(err error) {
	fmt.Fprintf(os.Stderr, "[error]: %s: %s\n", protocol, err)
}

func report(reporter chan string, ip net.IP, msg string) {
	reporter <- fmt.Sprintf("%-24s [%s] %s", ip, protocol, msg)
}

// Send an M-SEARCH packet on an UDP connection to a UDP destination address
func query(conn *net.UDPConn, dst *net.UDPAddr) {

	// Build SSDP request

	ssdpMsearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST:" + dst.String() + "\r\n" +
		"MAN:\"ssdp:discover\"\r\n" +
		"ST: ssdp:all\r\n" +
		"MX: 1\r\n\r\n"

	// Send

	_, err := conn.WriteToUDP([]byte(ssdpMsearch), dst)
	if err != nil {
		logError(err)
		return
	}
}

// Send an M-SEARCH packet on an UDP connection to a UDP destination address
func listen(conn *net.UDPConn, reporter reporter.Reporter) {
	buffer := make([]byte, 1024)

	for {
		// Read

		size, src, err := conn.ReadFromUDP(buffer)
		if err != nil {
			logError(err)
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

// Scan queries and listens for SSDP multicast on all interfaces.
func Scan(ifaces []net.Interface, output chan string) {
	reporter := reporter.New(output, protocol)

	for _, iface := range ifaces {
		ifAddrs, err := iface.Addrs()
		if err != nil {
			logError(err)
			continue
		}
		for _, ifAddr := range ifAddrs {
			ip, _, err := net.ParseCIDR(ifAddr.String())
			if err != nil {
				logError(err)
				continue
			}

			var multicastAddr net.UDPAddr
			if ip.To4() != nil {
				multicastAddr = ssdp4UDPAddress
			} else {
				multicastAddr = ssdp6UDPAddress
			}

			ifAddrUDP := net.UDPAddr{IP: ip, Port: 0, Zone: iface.Name}
			ifAddrConn, err := net.ListenUDP("udp", &ifAddrUDP)
			if err != nil {
				logError(err)
				continue
			}

			go listen(ifAddrConn, reporter)

			query(ifAddrConn, &multicastAddr)
		}
	}
}
