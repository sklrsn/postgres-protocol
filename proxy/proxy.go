package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
)

type Direction string

const (
	DirectionProxyToPostgres Direction = "Proxy <--> Postgres"
	DirectionClientToProxy   Direction = "Client <--> Proxy"
)

func (p *Proxy) AddConnection(conn Connection) {
	p.mux.Lock()
	defer p.mux.Unlock()
	p.Connections = append(p.Connections, conn)
}

func (p *Proxy) Write(conn net.Conn, msg []byte) (int, error) {
	return conn.Write(msg)
}

func (p *Proxy) Read(conn net.Conn) ([]byte, int, error) {
	buffer := make([]byte, 4096)
	length, err := conn.Read(buffer)
	return buffer, length, err
}

// XXX: Fatal for now
func (p *Proxy) SendStartupRequest(conn net.Conn) (int, error) {
	m := make(map[string]string)
	m["application_name"] = "psql"
	msg := CreateStartupMessage("postgres", "postgres", m)
	n, err := p.Write(conn, msg)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) SendPasswordResponse(conn net.Conn) (int, error) {
	msg := CreatePasswordResponseMessage("postgres")
	n, err := p.Write(conn, msg)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) IsAuthenticationOk(msg []byte) bool {
	return IsAuthenticationOk(msg)
}

func (p *Proxy) SendAuthenticationCleartextPasswordRequest(conn net.Conn) (int, error) {
	message := AuthenticationClearTextPasswordRequestMessage()
	n, err := p.Write(conn, message)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) SendAuthenticationOKResponse(conn net.Conn) (int, error) {
	message := AuthenticationOkResponseMessage()
	n, err := p.Write(conn, message)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) SendParameterStatus(conn net.Conn, key, value string) (int, error) {
	message := ParameterStatusMessage(key, value)
	n, err := p.Write(conn, message)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) SendBackendKeyData(conn net.Conn, pid, key int32) (int, error) {
	message := BackendKeyDataMessage(pid, key)
	n, err := p.Write(conn, message)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) SendReadyForQuery(conn net.Conn) (int, error) {
	message := ReadyForQueryMessage()
	n, err := p.Write(conn, message)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) SendSSLResponse(conn net.Conn, sslCode byte) (int, error) {
	message := SSLResponseMessage(sslCode)
	n, err := p.Write(conn, message)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) UpgradeServerConnection(conn net.Conn) net.Conn {
	crt, err := tls.LoadX509KeyPair("/opt/bin/proxy-crt.pem", "/opt/bin/proxy-key.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}
	ca, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return tls.Server(conn, &tls.Config{
		RootCAs:            ca,
		Certificates:       []tls.Certificate{crt},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	})
}

func (p *Proxy) SendSSLRequest(conn net.Conn) (int, error) {
	message := SSLRequestMessage()
	n, err := p.Write(conn, message)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

func (p *Proxy) UpgradeClientConnection(conn net.Conn) net.Conn {
	crt, err := tls.LoadX509KeyPair("/opt/bin/proxy-crt.pem", "/opt/bin/proxy-key.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}
	ca, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return tls.Client(conn, &tls.Config{
		RootCAs:            ca,
		Certificates:       []tls.Certificate{crt},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	})
}

func (p *Proxy) Intercept(src net.Conn, dst net.Conn) {
	//1. Client <---> Proxy
	msg, n, err := p.Read(src)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("startup message(client): msg=%v length=%v", hex.Dump(msg), n)
	version := GetVersion(msg)
	if version == SSLRequestCode {
		// Send SSL allowed for the connection
		p.SendSSLResponse(src, SSLAllowed)
		// Upgrade connection to TLS
		src = p.UpgradeServerConnection(src)
		// Read response of client for the SSL acknowledgement
		msg, n, err = p.Read(src)
		if err != nil {
			log.Fatal(err)
		}
	}
	//Ask client for password
	p.SendAuthenticationCleartextPasswordRequest(src)
	// Read client password
	msg, n, err = p.Read(src)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("password (from client):%v", hex.Dump(msg))

	// Send AuthenticationOk
	p.SendAuthenticationOKResponse(src)
	// Send Parameter Status
	p.SendParameterStatus(src, "application_name", "psql")
	// Send Parameter Status
	p.SendParameterStatus(src, "client_encoding", "UTF8")
	// Send Parameter Status
	p.SendParameterStatus(src, "DateStyle", "ISO, MDY")
	// Send Parameter Status
	p.SendParameterStatus(src, "integer_datetimes", "on")
	// Send Parameter Status
	p.SendParameterStatus(src, "IntervalStyle", "postgres")
	// Send Parameter Status
	p.SendParameterStatus(src, "is_superuser", "on")
	// Send Parameter Status
	p.SendParameterStatus(src, "server_version", "12.14 (Debian 12.14-1.pgdg110+1)")
	// Send Parameter Status
	p.SendParameterStatus(src, "session_authorization", "postgres")
	// Send Parameter Status
	p.SendParameterStatus(src, "standard_conforming_strings", "on")
	// Send Parameter Status
	p.SendParameterStatus(src, "TimeZone", "Etc/UTC")
	// Send Backend KeyData
	p.SendBackendKeyData(src, 108, 304016105)
	// Send ReadyForQuery
	p.SendReadyForQuery(src)

	log.Println("success: client negotiation (Client <--> Proxy) done.")

	// 2. Proxy <--> Postgres
	switch os.Getenv("PGSSLMODE") {
	case "require":
		p.SendSSLRequest(dst)

		msg, length, err := p.Read(dst)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("ssl response (postgres -> proxy): msg=%v length=%v", hex.Dump(msg), length)

		dst = p.UpgradeClientConnection(dst)
	}

	p.SendStartupRequest(dst)

	msg, length, err := p.Read(dst)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("startup message response (postgres -> proxy): msg=%v length=%v", hex.Dump(msg), length)

	p.SendPasswordResponse(dst)

	msg, length, err = p.Read(dst)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("password response (postgres -> proxy): msg=%v length=%v", hex.Dump(msg), length)

	if !p.IsAuthenticationOk(msg) {
		log.Fatal("Authentication failed")
	}
	log.Println("success: Server (Proxy <--> PostgresDB) negotiation done")

	// 3.
	go func() {
		defer func() {
			_ = src.Close()
			_ = dst.Close()
		}()
		_, _ = io.Copy(dst, src)
	}()

	go func() {
		defer func() {
			_ = src.Close()
			_ = dst.Close()
		}()
		_, _ = io.Copy(src, dst)
	}()
}

func (p *Proxy) HandleConnection(src net.Conn, dst net.Conn) {
	p.Intercept(src, dst)
}

func (p *Proxy) Passthrough(src net.Conn, dst net.Conn) {
}
