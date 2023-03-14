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
func CreatePasswordResponseMessage(password string) (_ []byte, err error) {
	message := NewMessageBuffer()
	if err = message.WriteByte(MessageTypePasswordResponse); err != nil {
		return
	}
	if _, err = message.WriteInt32(0); err != nil {
		return
	}
	if _, err = message.WriteString(password); err != nil {
		return
	}
	message.ResetLength(PostgresMessageLengthOffset)
	return message.Bytes(), nil
}

/**
 * StartupMessage (F)
 *
 * To begin a session, a frontend opens a connection to the server and sends a startup message.
 * This message includes the names of the user and of the database the user wants to connect to;
 * it also identifies the particular protocol version to be used
 */
func CreateStartupMessage(username string, database string, options map[string]string) (_ []byte, err error) {
	message := NewMessageBuffer()
	if _, err = message.WriteInt32(0); err != nil {
		return
	}
	if _, err = message.WriteInt32(ProtocolVersion); err != nil {
		return
	}
	if _, err = message.WriteString(ConnectionAttributeUser); err != nil {
		return
	}
	if _, err = message.WriteString(username); err != nil {
		return
	}
	if _, err = message.WriteString(ConnectionAttributeDatabase); err != nil {
		return
	}
	if _, err = message.WriteString(database); err != nil {
		return
	}
	for option, value := range options {
		if _, err = message.WriteString(option); err != nil {
			return
		}
		if _, err = message.WriteString(value); err != nil {
			return
		}
	}
	if err = message.WriteByte(0x00); err != nil {
		return
	}
	message.ResetLength(PostgresMessageLengthOffsetStartup)
	return message.Bytes(), nil
}

/**
 * SSLRequest (F)
 *
 * To initiate an SSL-encrypted connection, the frontend initially sends an SSLRequest message rather than a StartupMessage.
 * The server then responds with a single byte containing S or N, indicating that it is willing or unwilling to perform SSL, respectively.
 */
func SSLRequestMessage() (_ []byte, err error) {
	message := NewMessageBuffer()
	if _, err = message.WriteInt32(8); err != nil {
		return
	}
	if _, err = message.WriteInt32(SSLRequestCode); err != nil {
		return
	}
	return message.Bytes(), nil
}
