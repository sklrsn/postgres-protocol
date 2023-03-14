package main

import (
	"net"
	"sync"
)

const (
	FrontendApplicationNamePsql  = "psql"
	FrontendApplicationNamePrivX = "privx"
)

type PGConnection struct {
	Conn        net.Conn
	C           chan Packet
	username    string
	password    string
	database    string
	application string
	cmutex      sync.Mutex
	certFile    string
	keyFile     string
}

type Packet struct {
	Body   []byte
	Error  error
	Length int
}

func (pg *PGConnection) Close() error {
	return pg.Conn.Close()
}

func (pg *PGConnection) SendMessage(msg []byte) Packet {
	length, err := pg.Conn.Write(msg)
	return Packet{Body: nil, Length: length, Error: err}
}

func (pg *PGConnection) ReceiveMessage() Packet {
	buffer := make([]byte, 4096)
	length, err := pg.Conn.Read(buffer)
	return Packet{Body: buffer, Length: length, Error: err}
}

func (pg *PGConnection) sendStartupMessage() {
	params := make(map[string]string)
	params[ConnectionAttributeApplicationName] = pg.application
	msg, err := CreateStartupMessage(pg.username, pg.password, params)
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(msg)
}

func (pg *PGConnection) sendPasswordResponse() {
	msg, err := CreatePasswordResponseMessage(pg.password)
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(msg)
}

func (pg *PGConnection) isAuthenticationOK(msg []byte) bool {
	authType, err := GetAuthenticationType(msg)
	pg.C <- Packet{Error: err}
	return AuthenticationOK == authType
}

func (pg *PGConnection) sendAuthenticationClearTextPasswordRequest() {
	msg, err := AuthenticationClearTextPasswordRequestMessage()
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(msg)
}

func (pg *PGConnection) sendAuthenticationOKResponse() {
	message, err := AuthenticationOkResponseMessage()
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendParameterStatus(key, value string) {
	message, err := ParameterStatusMessage(key, value)
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendBackendKeyData(pid, key int32) {
	message, err := BackendKeyDataMessage(pid, key)
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendReadyForQuery() {
	message, err := ReadyForQueryMessage()
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendSSLRequest() {
	message, err := SSLRequestMessage()
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendSSLResponse(sslCode byte) {
	message, err := SSLResponseMessage(sslCode)
	pg.C <- Packet{Error: err}
	pg.C <- pg.SendMessage(message)
}
