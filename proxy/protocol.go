package main

import (
	"bytes"
	"encoding/binary"
)

/**
 * Frontend/Backend Protocol
 *
 * https://www.postgresql.org/docs/current/protocol.html
 */

/** Message Offset */
const (
	PostgresMessageLengthOffsetStartup int = 0
	PostgresMessageLengthOffset        int = 1
)

const (
	/**
	 * The protocol version number.
	 * The most significant 16 bits are the major version number (3 for the protocol described here).
	 * The least significant 16 bits are the minor version number (0 for the protocol described here).
	 */
	ProtocolVersion int32 = 196608
	/**
	 * The SSL request code.
	 * The value is chosen to contain 1234 in the most significant 16 bits, and 5679 in the least significant 16 bits.
	 */
	SSLRequestCode int32 = 80877103
)

/* SSL Responses */
const (
	SSLAllowed    byte = 'S'
	SSLNotAllowed byte = 'N'
)

const (
	//Identifies the message as an authentication request (B)
	MessageTypeAuthentication byte = 'R'
	//Identifies the message as a password response (F)
	MessageTypePasswordResponse byte = 'p'
	//Identifies the message as a run-time parameter status report (B)
	MessageTypeParameterStatus byte = 'S'
	//Identifies the message as cancellation key data (B)
	MessageTypeBackendKeyData byte = 'K'
	//Identifies the message type ReadyForQuery which is sent whenever the backend is ready for a new query cycle (B)
	MessageTypeReadyForQuery byte = 'Z'
	//Identifies the message as a termination (F)
	MessageTypeTerminate byte = 'X'
	//Identifies the message as a simple query (F)
	MessageTypeQuery byte = 'Q'
)

/** Current backend transaction status indicator */
const (
	//Idle (not in a transaction block)
	TransactionStatusIdle byte = 'I'
	//Transaction block
	TransactionStatusInTransaction byte = 'T'
	//Failed transaction block
	TransactionStatusFailed byte = 'E'
)

const (
	//Identifies the message as an authentication request. Specifies that the authentication was successful
	AuthenticationOK int32 = 0
	//Identifies the message as an authentication request. Specifies that Kerberos V5 authentication is required.
	AuthenticationKerberosV5 int32 = 2
	//Identifies the message as an authentication request. Specifies that a clear-text password is required
	AuthenticationClearTextPassword int32 = 3
	//Identifies the message as an authentication request. Specifies that an MD5-encrypted password is required.
	AuthenticationMD5 int32 = 5
	//Identifies the message as an authentication request. Specifies that an SCM credentials message is required.
	AuthenticationSCM int32 = 6
	//Identifies the message as an authentication request. Specifies that GSSAPI authentication is required.
	AuthenticationGSS int32 = 7
	//Identifies the message as an authentication request. Specifies that this message contains GSSAPI or SSPI data.
	AuthenticationGSSContinue int32 = 8
	//Identifies the message as an authentication request. Specifies that SSPI authentication is required.
	AuthenticationSSPI int32 = 9
)

func GetMessageType(message []byte) byte {
	return message[0]
}

func GetVersion(message []byte) int32 {
	var code int32
	reader := bytes.NewReader(message[4:8])
	binary.Read(reader, binary.BigEndian, &code)
	return code
}

func IsAuthenticationOk(message []byte) bool {
	var msgLength int32
	var authType int32
	reader := bytes.NewReader(message[1:5])
	binary.Read(reader, binary.BigEndian, &msgLength)
	reader.Reset(message[5:9])
	binary.Read(reader, binary.BigEndian, &authType)
	return msgLength == 8 && AuthenticationOK == authType
}

/** Connection Attributes */
const (
	ConnectionAttributeApplicationName = "application_name"
	ConnectionAttributeUser            = "user"
	ConnectionAttributeDatabase        = "database"
)

func GetStartupMessageAttributes(msg []byte) (m map[string]string) {
	m = make(map[string]string)
	buf := bytes.NewBuffer(msg)
	bs := make([]byte, 4)
	if _, err := buf.Read(bs); err != nil { //Message length
		return //ignore
	}
	if _, err := buf.Read(bs); err != nil { //Message opcode
		return //ignore
	}
	// Startup attributes (if any)
	for {
		key, err := buf.ReadString(0x00)
		if err != nil || len(key) == 0 {
			return
		}
		value, err := buf.ReadString(0x00)
		if err != nil || len(value) == 0 {
			return
		}
		m[key] = value
	}
}

func GetPasswordFromPasswordMessage(msg []byte) (password string) {
	buf := bytes.NewBuffer(msg)
	if _, err := buf.ReadByte(); err != nil { //Message opcode
		return //ignore
	}
	bs := make([]byte, 4)
	if _, err := buf.Read(bs); err != nil { //Message length
		return //ignore
	}
	password, err := buf.ReadString(0x00)
	if err != nil {
		return
	}
	return
}
