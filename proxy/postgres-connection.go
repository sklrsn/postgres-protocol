package main

import (
	"net"
	"sync"
)

const (
	FrontendApplicationNamePsql  = "psql"
	FrontendApplicationNamePrivX = "privx"
)

type DBConnection struct {
	Conn        net.Conn
	C           chan Packet
	username    string
	password    string
	database    string
	application string
	cmutex      sync.Mutex
}

type Packet struct {
	Body   []byte
	Error  error
	Length int
}

func (dbc *DBConnection) Close() error {
	return dbc.Conn.Close()
}

func (dbc *DBConnection) SendMessage(msg []byte) Packet {
	length, err := dbc.Conn.Write(msg)
	return Packet{Body: nil, Length: length, Error: err}
}

func (dbc *DBConnection) ReceiveMessage() Packet {
	buffer := make([]byte, 4096)
	length, err := dbc.Conn.Read(buffer)
	return Packet{Body: buffer, Length: length, Error: err}
}

func (dbc *DBConnection) sendStartupMessage() {
	params := make(map[string]string)
	params[ConnectionAttributeApplicationName] = dbc.application
	msg := CreateStartupMessage(dbc.username, dbc.password, params)
	dbc.C <- dbc.SendMessage(msg)
}

func (dbc *DBConnection) sendPasswordResponse() {
	msg := CreatePasswordResponseMessage(dbc.password)
	dbc.C <- dbc.SendMessage(msg)
}

func (dbc *DBConnection) isAuthenticationOK(msg []byte) bool {
	return len(msg) > 0 && IsAuthenticationOk(msg)
}

func (dbc *DBConnection) sendAuthenticationClearTextPasswordRequest() {
	msg := AuthenticationClearTextPasswordRequestMessage()
	dbc.C <- dbc.SendMessage(msg)
}

func (dbc *DBConnection) sendAuthenticationOKResponse() {
	message := AuthenticationOkResponseMessage()
	dbc.C <- dbc.SendMessage(message)
}

func (dbc *DBConnection) sendParameterStatus(key, value string) {
	message := ParameterStatusMessage(key, value)
	dbc.C <- dbc.SendMessage(message)
}

func (dbc *DBConnection) sendBackendKeyData(pid, key int32) {
	message := BackendKeyDataMessage(pid, key)
	dbc.C <- dbc.SendMessage(message)
}

func (dbc *DBConnection) sendReadyForQuery() {
	message := ReadyForQueryMessage()
	dbc.C <- dbc.SendMessage(message)
}

func (dbc *DBConnection) sendSSLRequest() {
	message := SSLRequestMessage()
	dbc.C <- dbc.SendMessage(message)
}

func (dbc *DBConnection) sendSSLResponse(sslCode byte) {
	message := SSLResponseMessage(sslCode)
	dbc.C <- dbc.SendMessage(message)
}
