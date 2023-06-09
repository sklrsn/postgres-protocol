package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"sync"
)

/**

Frontend(F)                                    Backend(B)
|             SSL Request ('S' or 'N')           |
|----------------------------------------------->|
|                                                |
|             SSL Response ('S')                 |
|<-----------------------------------------------|
|                                                |
|             Startup Message                    |
|----------------------------------------------->|
|                                                |
|             Password Request                   |
|<-----------------------------------------------|
|                                                |
|             Password Response                  |
|----------------------------------------------->|
|                                                |
|             AuthenticationOK                   |
|<-----------------------------------------------|
|                                                |
|             Parameter Status                   |
|<-----------------------------------------------|
|                                                |
|             Parameter Status                   |
|<-----------------------------------------------|
|                                                |
|             Parameter Status                   |
|<-----------------------------------------------|
|                                                |
|             BackendKeyData                     |
|<-----------------------------------------------|
|                                                |
|             ReadyForQuery                      |
|<-----------------------------------------------|
|                                                |

*/

const (
	PostgresApplicationNamePsql    = "psql"
	PostgresApplicationNamePrivX   = "privx"
	PostgresApplicationNameUnknown = "unknown"
)

type PostgresProxy struct {
	ForwardConnection *PGConnection //Backend
	ReverseConnection *PGConnection //Frontend
	forwardChannel    chan struct{}
	reverseChannel    chan struct{}
	pmutex            sync.Mutex
	channelRecorder   ChannelRecorder
}

func (proxy *PostgresProxy) UpgradeReverseConnection() error {
	ca, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	proxy.ReverseConnection.Conn =
		tls.Server(proxy.ReverseConnection.Conn, &tls.Config{
			RootCAs:            ca,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				crt, err := tls.LoadX509KeyPair(proxy.ReverseConnection.certFile, proxy.ReverseConnection.keyFile)
				if err != nil {
					return nil, err
				}
				return &crt, err
			},
		})
	return nil
}

func (proxy *PostgresProxy) UpgradeForwardConnection() error {
	crt, err := tls.LoadX509KeyPair(proxy.ForwardConnection.certFile, proxy.ForwardConnection.keyFile)
	if err != nil {
		return err
	}
	ca, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	proxy.ForwardConnection.Conn =
		tls.Client(proxy.ForwardConnection.Conn, &tls.Config{
			RootCAs:            ca,
			Certificates:       []tls.Certificate{crt},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		})
	return nil
}

func (proxy *PostgresProxy) forwardConnectionHandshake() {
	go func() {
		for {
			select {
			case packet := <-proxy.ForwardConnection.C:
				if packet.Error != nil {
					_ = proxy.Close()
					return
				}
			case <-proxy.forwardChannel:
				return
			}
		}
	}()
	// Send SSL request to backend
	proxy.ForwardConnection.sendSSLRequest()
	// Read backend response
	packet := proxy.ForwardConnection.ReceiveMessage()
	if packet.Error != nil {
		_ = proxy.Close()
	}
	// Terminate Connection if backend doesn't support SSL
	if packet.Body != nil && len(packet.Body) > 0 && packet.Body[0] == SSLNotAllowed {
		_ = proxy.Close()
	}
	// Upgrade tls client connection
	if err := proxy.UpgradeForwardConnection(); err != nil {
		_ = proxy.Close()
	}
	// Send startup request to backend
	proxy.ForwardConnection.sendStartupMessage()
	// Read response for startup message from backend
	packet = proxy.ForwardConnection.ReceiveMessage()
	if packet.Error != nil {
		_ = proxy.Close()
	}

	authType, err := GetAuthenticationType(packet.Body)
	if err != nil {
		_ = proxy.Close()
	}
	switch authType {
	case AuthenticationClearTextPassword:
		// Send the clearText password response
		proxy.ForwardConnection.sendPasswordResponse()
	default:
		log.Println("auth type not supported")
		_ = proxy.Close()
		return
	}

	// Read backend's authentication response
	packet = proxy.ForwardConnection.ReceiveMessage()
	if packet.Error != nil {
		_ = proxy.Close()
	}
	// Check backend authentication status
	if !proxy.ForwardConnection.isAuthenticationOK(packet.Body) {
		_ = proxy.Close()
	}
}

func (proxy *PostgresProxy) reverseConnectionHandshake() {
	go func() {
		for {
			select {
			case packet := <-proxy.ReverseConnection.C:
				if packet.Error != nil {
					_ = proxy.Close()
					return
				}
			case <-proxy.reverseChannel:
				return
			}
		}
	}()
	// Read frontend startup message
	packet := proxy.ReverseConnection.ReceiveMessage()
	if packet.Error != nil {
		_ = proxy.Close()
	}
	// Check SSL request or startup message
	version, err := GetVersion(packet.Body)
	if err != nil {
		_ = proxy.Close()
	}
	if SSLRequestCode == version {
		// Send SSL allowed response to backend
		proxy.ReverseConnection.sendSSLResponse(SSLAllowed)
		// Upgrade tls server connection
		if err := proxy.UpgradeReverseConnection(); err != nil {
			_ = proxy.Close()
		}
		// Read startup message from frontend (one more time)
		packet = proxy.ReverseConnection.ReceiveMessage()
		if packet.Error != nil {
			_ = proxy.Close()
		}
	}
	// Send clear text password request to backend
	proxy.ReverseConnection.sendAuthenticationClearTextPasswordRequest()
	// Read frontend password
	packet = proxy.ReverseConnection.ReceiveMessage()
	if packet.Error != nil {
		_ = proxy.Close()
	}
	// Send AuthenticationOk
	proxy.ReverseConnection.sendAuthenticationOKResponse()
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("application_name", "psql")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("client_encoding", "UTF8")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("DateStyle", "ISO, MDY")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("integer_datetimes", "on")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("IntervalStyle", "postgres")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("is_superuser", "on")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("server_version", "12.14 (Debian 12.14-1.pgdg110+1)")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("session_authorization", "postgres")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("standard_conforming_strings", "on")
	// Send Parameter Status
	proxy.ReverseConnection.sendParameterStatus("TimeZone", "Etc/UTC")
	// Send Backend KeyData
	proxy.ReverseConnection.sendBackendKeyData(rand.Int31n(math.MaxInt32), rand.Int31n(math.MaxInt32))
	// Send ReadyForQuery
	proxy.ReverseConnection.sendReadyForQuery()
}

func (proxy *PostgresProxy) Connect() {
	proxy.forwardConnectionHandshake()
	proxy.reverseConnectionHandshake()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()
		proxy.transfer(proxy.ForwardConnection.Conn, proxy.ReverseConnection.Conn)
	}()

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()
		proxy.transfer(proxy.ReverseConnection.Conn, proxy.ForwardConnection.Conn)
	}()
	wg.Wait()
}

func (proxy *PostgresProxy) transfer(src, dst net.Conn) {
	defer func() {
		_ = src.Close()
		_ = dst.Close()
	}()

	go proxy.channelRecorder.Watch()
	dest := io.MultiWriter(dst, proxy.channelRecorder)
	n, err := io.Copy(dest, src)
	if err != nil {
		log.Println(err)
	}
	log.Printf("postgres-proxy: transferred %d bytes", n)
}

func (proxy *PostgresProxy) Close() error {
	proxy.forwardChannel <- struct{}{}
	proxy.reverseChannel <- struct{}{}
	proxy.channelRecorder.Close()

	if err := proxy.ForwardConnection.Close(); err != nil {
		return err
	}
	if err := proxy.ReverseConnection.Close(); err != nil {
		return err
	}
	return nil
}
