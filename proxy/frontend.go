package main

/**
 * Message Formats
 * https://www.postgresql.org/docs/current/protocol-message-formats.html
 *
 * Frontend (F)
 */

/**
 * PasswordMessage (F)
 *
 * The server then sends an appropriate authentication request message,
 *  to which the frontend must reply with an appropriate authentication response message (such as a password)
 */
func CreatePasswordResponseMessage(password string) []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypePasswordResponse)
	message.WriteInt32(0)
	message.WriteString(password)
	message.ResetLength(PostgresMessageLengthOffset)
	return message.Bytes()
}

/**
 * StartupMessage (F)
 *
 * To begin a session, a frontend opens a connection to the server and sends a startup message.
 * This message includes the names of the user and of the database the user wants to connect to;
 * it also identifies the particular protocol version to be used
 */
func CreateStartupMessage(username string, database string, options map[string]string) []byte {
	message := NewMessageBuffer()
	message.WriteInt32(0)
	message.WriteInt32(ProtocolVersion)
	message.WriteString(ConnectionAttributeUser)
	message.WriteString(username)
	message.WriteString(ConnectionAttributeDatabase)
	message.WriteString(database)
	for option, value := range options {
		message.WriteString(option)
		message.WriteString(value)
	}
	message.WriteByte(0x00)
	message.ResetLength(PostgresMessageLengthOffsetStartup)
	return message.Bytes()
}

/**
 * SSLRequest (F)
 *
 * To initiate an SSL-encrypted connection, the frontend initially sends an SSLRequest message rather than a StartupMessage.
 * The server then responds with a single byte containing S or N, indicating that it is willing or unwilling to perform SSL, respectively.
 */
func SSLRequestMessage() []byte {
	message := NewMessageBuffer()
	message.WriteInt32(8)
	message.WriteInt32(SSLRequestCode)
	return message.Bytes()
}
