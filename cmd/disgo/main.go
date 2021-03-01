package main

import (
	"fmt"
	"net"

	"github.com/steabert/disgo/lib"
)

func main() {
	// Channel to collect the output when IP was discovered.
	out := make(chan string)
	ssdpReporter := lib.NewReporter(out, lib.SSDPProtocolName)
	mdnsReporter := lib.NewReporter(out, lib.MDNSProtocolName)

	// Loop over interfaces to start listening for multicast.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range ifaces {

		// Passive listeners on the interface.
		go lib.MDNSListenMulticast("udp4", iface, mdnsReporter)
		go lib.MDNSListenMulticast("udp6", iface, mdnsReporter)

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
			go lib.SSDPScan(ifAddrUDP, ssdpReporter)
			go lib.MDNSScan(ifAddrUDP, mdnsReporter)
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
