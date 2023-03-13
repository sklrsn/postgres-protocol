package main

import (
	"log"
	"net"
	"sync"
)

type Connection struct {
	ID string
}

type Proxy struct {
	Connections []Connection
	mux         sync.Mutex
}

func init() {
	log.SetFlags(log.LUTC | log.Lshortfile)
}

func main() {
	listener, err := net.Listen("tcp", ":8989")
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Println("listener is ready for connections at 8989")
	for {
		src, err := listener.Accept()
		if err != nil {
			log.Fatalf("%v", err)
		}
		log.Printf("new connection from psql client: %v", src.RemoteAddr().String())

		go func() {
			dst, err := net.Dial("tcp", "postgres:5432")
			if err != nil {
				log.Fatal(err)
			}

			// proxy := new(Proxy)
			// proxy.HandleConnection(src, dst)

			postgresProxy := PostgresProxy{
				ForwardConnection: &DBConnection{
					Conn:        dst,
					username:    "postgres",
					password:    "postgres",
					database:    "postgres",
					application: "psql",
					C:           make(chan Packet, 1024),
				},
				ReverseConnection: &DBConnection{
					Conn: src,
					C:    make(chan Packet, 1024),
				},
			}
			postgresProxy.Connect()

			log.Printf("connected to postgres server at %v", dst.RemoteAddr().String())
		}()
	}
}
