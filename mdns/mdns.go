package mdns

import (
	"fmt"
	"net"
	"os"

	"github.com/miekg/dns"
	"github.com/steabert/disgo/reporter"
)

// mDNS

const (
	mdns4Address = "224.0.0.251"
	mdns6Address = "ff02::fb"
	mdnsPort     = 5353
	// Protocol name of the multicast protocol.
	Protocol = "mDNS"
)

var (
	mdns4UDPAddress = net.UDPAddr{IP: net.ParseIP(mdns4Address), Port: mdnsPort}
	mdns6UDPAddress = net.UDPAddr{IP: net.ParseIP(mdns6Address), Port: mdnsPort}
)

func logError(err error) {
	fmt.Fprintf(os.Stderr, "[error]: %s: %s\n", Protocol, err)
}

func query(conn *net.UDPConn, dst *net.UDPAddr) {

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
		logError(err)
		return
	}

	// Send

	_, err = conn.WriteToUDP(data, dst)
	if err != nil {
		logError(err)
		return
	}
}

// listen watches a UDP connection for mDNS messages.
func listen(conn *net.UDPConn, reporter reporter.Reporter) {
	buffer := make([]byte, 1024)

	for {
		// Read

		size, src, err := conn.ReadFromUDP(buffer)
		if err != nil {
			logError(err)
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buffer[:size]); err != nil {
			logError(err)
			return
		}

		// Log

		for _, answer := range msg.Answer {
			reporter.Print(src.IP, answer.String())
		}
	}
}

// ListenMulticast listens for mDNS multicast on the provided interface.
func ListenMulticast(network string, iface net.Interface, out reporter.Reporter) {
	var multicastAddr net.UDPAddr
	if network == "udp4" {
		multicastAddr = mdns4UDPAddress
	} else if network == "udp6" {
		multicastAddr = mdns6UDPAddress
	} else {
		panic("unsupported network")
	}

	mdnsMulticastConn, err := net.ListenMulticastUDP(network, &iface, &multicastAddr)
	if err != nil {
		logError(err)
		return
	}
	listen(mdnsMulticastConn, out)
}

// Scan queries and listens for mDNS multicast on the provided address.
func Scan(ifSockAddr net.UDPAddr, out reporter.Reporter) {

	var multicastAddr net.UDPAddr
	if ifSockAddr.IP.To4() != nil {
		multicastAddr = mdns4UDPAddress
	} else {
		multicastAddr = mdns6UDPAddress
	}

	ifAddrConn, err := net.ListenUDP("udp", &ifSockAddr)
	if err != nil {
		logError(err)
		return
	}

	// Send question to multicast and listen for unicast reponses on interfaces addresses.
	query(ifAddrConn, &multicastAddr)
	listen(ifAddrConn, out)
}
