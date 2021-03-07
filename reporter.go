package disgo

import (
	"fmt"
	"net"
)

// Reporter provides custom printing to output channel
type Reporter struct {
	output   chan string
	protocol string
}

// NewReporter creates a new reporter.
func NewReporter(output chan string, protocol string) Reporter {
	return Reporter{output, protocol}
}

// Print prints an IP + message to the reporter's output channel
func (r Reporter) Print(ip net.IP, msg string) {
	r.output <- fmt.Sprintf("%-24s %-8s %s", ip, r.protocol, msg)
}
