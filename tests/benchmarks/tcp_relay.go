// A standalone TCP relay for throughput comparisons; uses only the Go standard library.
//
// Build: go build -o /tmp/ww-go-tcp-relay tests/benchmarks/tcp_relay.go
// Run:   GOMAXPROCS=1 /tmp/ww-go-tcp-relay -listen 127.0.0.1:5202 -target 127.0.0.1:5201
//
// io.Copy preserves Go's TCP fast paths, including splice on supported Linux systems.
// This is a benchmark helper, not a WaterWall node or a userspace-copy-only baseline.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"time"
)

func relay(client *net.TCPConn, target string) {
	defer client.Close()
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	server := conn.(*net.TCPConn)
	defer server.Close()

	done := make(chan error, 2)
	copyDirection := func(dst, src *net.TCPConn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			// Forward EOF while allowing a response in the other direction.
			err = dst.CloseWrite()
		}
		done <- err
	}
	go copyDirection(server, client)
	go copyDirection(client, server)
	if err := <-done; err != nil {
		// An error must also wake the copy blocked in the other direction.
		client.Close()
		server.Close()
		log.Printf("relay: %v", err)
	}
	if err := <-done; err != nil {
		log.Printf("relay: %v", err)
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:5202", "TCP listen address")
	target := flag.String("target", "127.0.0.1:5201", "TCP destination address")
	flag.Parse()

	address, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Printf("TCP relay %s -> %s", listener.Addr(), *target)
	for {
		client, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}
		go relay(client, *target)
	}
}
