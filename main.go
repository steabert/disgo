package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

// mDNS

const (
	mdns4Address = "224.0.0.251"
	mdns6Address = "ff02::fb"
	mdnsPort     = 5353
)

var (
	mdns4UDPAddress = net.UDPAddr{IP: net.ParseIP(mdns4Address), Port: mdnsPort}
	mdns6UDPAddress = net.UDPAddr{IP: net.ParseIP(mdns6Address), Port: mdnsPort}
)

func sendMDNSQuestion(conn *net.UDPConn, dst *net.UDPAddr) {

	// Build DNS message

	m := new(dns.Msg)
	m.SetQuestion("_googlecast._tcp.local.", dns.TypePTR)
	// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	// Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	m.Question[0].Qclass |= 1 << 15
	m.RecursionDesired = false
	data, err := m.Pack()
	if err != nil {
		panic(err)
	}

	// Send

	_, err = conn.WriteToUDP(data, dst)
	if err != nil {
		panic(err)
	}
}

func readMDNSResponse(conn *net.UDPConn, logger chan string) {

	// Read

	buffer := make([]byte, 1024)
	size, src, err := conn.ReadFromUDP(buffer)
	if err != nil {
		panic(err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(buffer[:size]); err != nil {
		panic(err)
	}

	// Log

	for _, answer := range msg.Answer {
		logger <- fmt.Sprintf("%s %s", src.IP, answer.String())
	}
}

func mdnsScanner(ifaces []net.Interface, logger chan string) {
	for _, iface := range ifaces {

		// Join multicast group and listen.

		mdnsMulticastConn4, err := net.ListenMulticastUDP("udp4", &iface, &mdns4UDPAddress)
		if err != nil {
			panic(err)
		}
		go readMDNSResponse(mdnsMulticastConn4, logger)

		mdnsMulticastConn6, err := net.ListenMulticastUDP("udp6", &iface, &mdns6UDPAddress)
		if err != nil {
			panic(err)
		}
		go readMDNSResponse(mdnsMulticastConn6, logger)

		// Send question to multicast and listen for unicast reponses on interfaces addresses.

		ifAddrs, err := iface.Addrs()
		if err != nil {
			panic("failed to get addresses")
		}
		for _, ifAddr := range ifAddrs {
			ip, _, err := net.ParseCIDR(ifAddr.String())
			if err != nil {
				panic(err)
			}
			var multicastAddr net.UDPAddr
			if ip.To4() != nil {
				multicastAddr = mdns4UDPAddress
			} else {
				multicastAddr = mdns6UDPAddress
			}

			ifAddrUDP := net.UDPAddr{IP: ip, Port: 0, Zone: iface.Name}
			ifAddrConn, err := net.ListenUDP("udp", &ifAddrUDP)

			if err != nil {
				panic(err)
			}

			go readMDNSResponse(ifAddrConn, logger)

			sendMDNSQuestion(ifAddrConn, &multicastAddr)
		}
	}
}

// SSDP

const (
	ssdp4Address = "239.255.255.250"
	ssdp6Address = "ff0e::c"
	ssdpPort     = 1900
)

var (
	ssdp4UDPAddress = net.UDPAddr{IP: net.ParseIP(ssdp4Address), Port: ssdpPort}
	ssdp6UDPAddress = net.UDPAddr{IP: net.ParseIP(ssdp6Address), Port: ssdpPort}
)

// Send an M-SEARCH packet on an UDP connection to a UDP destination address
func sendSSDPMSearch(conn *net.UDPConn, dst *net.UDPAddr) {

	// Build SSDP request

	data := []byte("M-SEARCH * HTTP/1.1\r" +
		"Host:239.255.255.250:1900\r" +
		"Man:\"ssdp:discover\"\r" +
		"ST: ssdp:all\rMX: 1\r\n\r\n")

	// Send

	_, err := conn.WriteToUDP(data, dst)
	if err != nil {
		panic(err)
	}
}

// Send an M-SEARCH packet on an UDP connection to a UDP destination address
func readSSDPResponse(conn *net.UDPConn, logger chan string) {

	// Read

	buffer := make([]byte, 1024)
	size, src, err := conn.ReadFromUDP(buffer)
	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(bytes.NewReader(buffer[:size]))
	req := &http.Request{} // Needed for ReadResponse but doesn't have to be real
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		fmt.Printf("failed to parse SSDP response: %s", err)
	}
	headers := response.Header

	// Log

	logger <- fmt.Sprintf("%s %s", src.IP, headers["Server"][0])
}

func ssdpScanner(ifaces []net.Interface, logger chan string) {
	for _, iface := range ifaces {
		ifAddrs, err := iface.Addrs()
		if err != nil {
			panic("failed to get addresses")
		}
		for _, ifAddr := range ifAddrs {
			ip, _, err := net.ParseCIDR(ifAddr.String())
			if err != nil {
				panic(err)
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
				panic(err)
			}

			go readSSDPResponse(ifAddrConn, logger)

			sendSSDPMSearch(ifAddrConn, &multicastAddr)
		}
	}
}

// Scanning

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		panic("failed to get interfaces")
	}

	logger := make(chan string)

	go ssdpScanner(ifaces, logger)
	go mdnsScanner(ifaces, logger)

	for msg := range logger {
		fmt.Println(msg)
	}

}
