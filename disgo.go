package main

import (
	"fmt"
	"net"

	"github.com/steabert/disgo/mdns"
	"github.com/steabert/disgo/reporter"
	"github.com/steabert/disgo/ssdp"
)

func main() {
	// Channel to collect the output when IP was discovered.
	out := make(chan string)
	ssdpReporter := reporter.New(out, ssdp.Protocol)
	mdnsReporter := reporter.New(out, mdns.Protocol)

	// Loop over interfaces to start listening for multicast.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range ifaces {

		// Passive listeners on the interface.
		go mdns.ListenMulticast("udp4", iface, mdnsReporter)
		go mdns.ListenMulticast("udp6", iface, mdnsReporter)

		ifAddrs, err := iface.Addrs()
		if err != nil {
			panic(err)
		}
		for _, ifAddr := range ifAddrs {
			ipAddr, _, err := net.ParseCIDR(ifAddr.String())
			if err != nil {
				panic(err)
			}

			ifAddrUDP := net.UDPAddr{IP: ipAddr, Port: 0, Zone: iface.Name}

			// Active scan on the interface address.
			go ssdp.Scan(ifAddrUDP, ssdpReporter)
			go mdns.Scan(ifAddrUDP, mdnsReporter)
		}
	}

	logged := make(map[string]bool)
	for msg := range out {
		if logged[msg] {
			continue
		}
		logged[msg] = true
		fmt.Println(msg)
	}

}
