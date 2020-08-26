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

	reporter := make(chan string)

	ssdp.Scan(ifaces, reporter)
	mdns.Scan(ifaces, reporter)

	logged := make(map[string]bool)
	for msg := range reporter {
		if logged[msg] {
			continue
		}
		logged[msg] = true
		fmt.Println(msg)
	}

}
