package postgres

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"os"
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

const (
	PostgresApplicationName = "application_name"
)

type PostgresProxy struct {
	forwardConnection  net.Conn //Backend Connection
	reverseConnection  net.Conn //Frontend Connection
	C                  chan Packet
	mutex              sync.Mutex
	DBConnectionParams *DBConnectionParams
}

type DBConnectionParams struct {
	DatabaseName    string
	Username        string
	ApplicationName string
	Password        string
	RootCAs         *x509.CertPool
	CertFile        string
	KeyFile         string
}

type Packet struct {
	Message []byte
	Size    int
	Error   error
}

func (postgresProxy *PostgresProxy) ReceiveMessage(conn net.Conn) Packet {
	buffer := make([]byte, 4096)
	length, err := conn.Read(buffer)
	return Packet{Message: buffer, Size: length, Error: err}
}
func (postgresProxy *PostgresProxy) ReceiveStartupMessage() Packet {
	p := postgresProxy.ReceiveMessage(postgresProxy.reverseConnection)
	postgresProxy.C <- p
	return p
}

func (postgresProxy *PostgresProxy) SendMessage(conn net.Conn, msg []byte) Packet {
	n, err := conn.Write(msg)
	return Packet{Size: n, Error: err}
}

func (postgresProxy *PostgresProxy) SendStartupRequest() {
	params := make(map[string]string)
	params[PostgresApplicationName] = postgresProxy.DBConnectionParams.ApplicationName
	msg := CreateStartupMessage(postgresProxy.DBConnectionParams.Username,
		postgresProxy.DBConnectionParams.DatabaseName, params)
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.forwardConnection, msg)
}

func (postgresProxy *PostgresProxy) SendPasswordResponse() {
	msg := CreatePasswordResponseMessage(postgresProxy.DBConnectionParams.Password)
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.forwardConnection, msg)
}

func (postgresProxy *PostgresProxy) IsAuthenticationSuccess(msg []byte) bool {
	return IsAuthenticationOk(msg)
}

func (postgresProxy *PostgresProxy) SendAuthenticationClearTextPasswordRequest() {
	message := AuthenticationClearTextPasswordRequestMessage()
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.reverseConnection, message)
}

func (postgresProxy *PostgresProxy) ReceivePasswordResponse() Packet {
	p := postgresProxy.ReceiveMessage(postgresProxy.reverseConnection)
	postgresProxy.C <- p
	return p
}

func (postgresProxy *PostgresProxy) SendAuthenticationOKResponse() {
	message := AuthenticationOkResponseMessage()
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.reverseConnection, message)
}

func (postgresProxy *PostgresProxy) SendParameterStatus(key, value string) {
	message := ParameterStatusMessage(key, value)
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.reverseConnection, message)
}

func (postgresProxy *PostgresProxy) SendBackendKeyData(processID, secretKey int32) {
	message := BackendKeyDataMessage(processID, secretKey)
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.reverseConnection, message)
}

func (postgresProxy *PostgresProxy) SendReadyForQuery() {
	message := ReadyForQueryMessage()
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.reverseConnection, message)
}

func (postgresProxy *PostgresProxy) SendSSLResponse(sslCode byte) {
	message := SSLResponseMessage(sslCode)
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.reverseConnection, message)
}

func (postgresProxy *PostgresProxy) UpgradeServerConnection() {
	crt, err := tls.LoadX509KeyPair(postgresProxy.DBConnectionParams.CertFile,
		postgresProxy.DBConnectionParams.KeyFile)
	postgresProxy.C <- Packet{Error: err}

	ca, err := x509.SystemCertPool()
	postgresProxy.C <- Packet{Error: err}

	postgresProxy.reverseConnection = tls.Server(postgresProxy.reverseConnection,
		&tls.Config{
			RootCAs:            ca,
			Certificates:       []tls.Certificate{crt},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		})
}

func (postgresProxy *PostgresProxy) ReceiveReverseSSLAckResponse() Packet {
	p := postgresProxy.ReceiveMessage(postgresProxy.reverseConnection)
	postgresProxy.C <- p
	return p
}

func (postgresProxy *PostgresProxy) SendSSLRequest() {
	message := SSLRequestMessage()
	postgresProxy.C <- postgresProxy.SendMessage(postgresProxy.forwardConnection, message)
}

func (postgresProxy *PostgresProxy) ReceiveForwardSSLAckResponse() Packet {
	p := postgresProxy.ReceiveMessage(postgresProxy.forwardConnection)
	postgresProxy.C <- p
	return p
}

func (postgresProxy *PostgresProxy) ReceiveForwardPasswordResponse() Packet {
	p := postgresProxy.ReceiveMessage(postgresProxy.forwardConnection)
	postgresProxy.C <- p
	return p
}

func (postgresProxy *PostgresProxy) UpgradeClientConnection() {
	crt, err := tls.LoadX509KeyPair(postgresProxy.DBConnectionParams.CertFile,
		postgresProxy.DBConnectionParams.KeyFile)
	postgresProxy.C <- Packet{Error: err}

	ca, err := x509.SystemCertPool()
	postgresProxy.C <- Packet{Error: err}

	postgresProxy.forwardConnection = tls.Client(postgresProxy.forwardConnection,
		&tls.Config{
			RootCAs:            ca,
			Certificates:       []tls.Certificate{crt},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		})
}

func (postgresProxy *PostgresProxy) HandleDBConnection() {
	go func() {
		select {
		case packet := <-postgresProxy.C:
			// If any error Terminate forward and reverse connection.
			if packet.Error != nil {
				_ = postgresProxy.TerminateConnection()
			}
		}
	}()

	// Reverse Connection: Read frontend Startup message and negotiate ssl if required
	msg := postgresProxy.ReceiveStartupMessage()
	version := GetVersion(msg.Message)
	if version == SSLRequestCode {
		// Send SSL allowed for the connection
		postgresProxy.SendSSLResponse(SSLAllowed)
		// Upgrade backend connection to TLS
		postgresProxy.UpgradeServerConnection()
		// Read response of frontend for the SSL acknowledgement
		postgresProxy.ReceiveReverseSSLAckResponse()
	}
	// Send Password Request to frontend
	postgresProxy.SendAuthenticationClearTextPasswordRequest()
	// Read frontend password
	postgresProxy.ReceivePasswordResponse()
	// Send AuthenticationOk
	postgresProxy.SendAuthenticationOKResponse()
	// Send Parameter Status
	postgresProxy.SendParameterStatus("application_name", "psql")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("client_encoding", "UTF8")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("DateStyle", "ISO, MDY")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("integer_datetimes", "on")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("IntervalStyle", "postgres")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("is_superuser", "on")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("server_version", "12.14 (Debian 12.14-1.pgdg110+1)")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("session_authorization", "postgres")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("standard_conforming_strings", "on")
	// Send Parameter Status
	postgresProxy.SendParameterStatus("TimeZone", "Etc/UTC")
	// Send Backend KeyData
	postgresProxy.SendBackendKeyData(108, 304016105)
	// Send ReadyForQuery
	postgresProxy.SendReadyForQuery()

	log.Println("Success: ReverseConnection is established.")

	// Forward Connection: negotiate ssl
	switch os.Getenv("PGSSLMODE") {
	case "require":
		postgresProxy.SendSSLRequest()
		msg := postgresProxy.ReceiveForwardSSLAckResponse()
		if msg.Message[0] != SSLNotAllowed {
			_ = postgresProxy.TerminateConnection()
		}
		postgresProxy.UpgradeClientConnection()
	}
	// Send startup message
	postgresProxy.SendStartupRequest()
	// Send password response
	postgresProxy.SendPasswordResponse()
	// Read response for the password message
	msg = postgresProxy.ReceiveForwardPasswordResponse()
	if !postgresProxy.IsAuthenticationSuccess(msg.Message) {
		_ = postgresProxy.TerminateConnection()
	}
	log.Println("Success: ForwardConnection is established.")

	// 3.
	go func() {
		defer func() {
			_ = postgresProxy.TerminateConnection()
		}()
		_, _ = io.Copy(postgresProxy.forwardConnection, postgresProxy.reverseConnection)
	}()

	go func() {
		defer func() {
			_ = postgresProxy.TerminateConnection()
		}()
		_, _ = io.Copy(postgresProxy.reverseConnection, postgresProxy.forwardConnection)
	}()

}

func (postgresProxy *PostgresProxy) TerminateConnection() error {
	postgresProxy.mutex.Lock()
	defer postgresProxy.mutex.Unlock()
	if err := postgresProxy.forwardConnection.Close(); err != nil {
		return err
	}
	if err := postgresProxy.reverseConnection.Close(); err != nil {
		return err
	}
	return nil
}
