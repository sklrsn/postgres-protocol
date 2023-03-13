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
	certFile    string
	keyFile     string
	cmutex      sync.Mutex
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
	msg := CreateStartupMessage(pg.username, pg.password, params)
	pg.C <- pg.SendMessage(msg)
}

func (pg *PGConnection) sendPasswordResponse() {
	msg := CreatePasswordResponseMessage(pg.password)
	pg.C <- pg.SendMessage(msg)
}

func (pg *PGConnection) isAuthenticationOK(msg []byte) bool {
	return len(msg) > 0 && IsAuthenticationOk(msg)
}

func (pg *PGConnection) sendAuthenticationClearTextPasswordRequest() {
	msg := AuthenticationClearTextPasswordRequestMessage()
	pg.C <- pg.SendMessage(msg)
}

func (pg *PGConnection) sendAuthenticationOKResponse() {
	message := AuthenticationOkResponseMessage()
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendParameterStatus(key, value string) {
	message := ParameterStatusMessage(key, value)
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendBackendKeyData(pid, key int32) {
	message := BackendKeyDataMessage(pid, key)
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendReadyForQuery() {
	message := ReadyForQueryMessage()
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendSSLRequest() {
	message := SSLRequestMessage()
	pg.C <- pg.SendMessage(message)
}

func (pg *PGConnection) sendSSLResponse(sslCode byte) {
	message := SSLResponseMessage(sslCode)
	pg.C <- pg.SendMessage(message)
}
