package main

import (
	"fmt"
	"net"

	"github.com/steabert/disgo/mdns"
	"github.com/steabert/disgo/ssdp"
)

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		panic("failed to get interfaces")
	}

	logger := make(chan string)

	ssdp.Scan(ifaces, logger)
	mdns.Scan(ifaces, logger)

	logged := make(map[string]bool)
	for msg := range logger {
		if logged[msg] {
			continue
		}
		logged[msg] = true
		fmt.Println(msg)
	}

}
