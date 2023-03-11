package postgres

/**
 * Message Formats
 * https://www.postgresql.org/docs/current/protocol-message-formats.html
 *
 * (F)
 */

func CreatePasswordResponseMessage(password string) []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypePasswordResponse)
	message.WriteInt32(0)
	message.WriteString(password)
	message.ResetLength(PostgresMessageLengthOffset)
	return message.Bytes()
}

func CreateStartupMessage(username string, database string, options map[string]string) []byte {
	message := NewMessageBuffer()
	message.WriteInt32(0)
	message.WriteInt32(ProtocolVersion)
	message.WriteString("user")
	message.WriteString(username)
	message.WriteString("database")
	message.WriteString(database)
	for option, value := range options {
		message.WriteString(option)
		message.WriteString(value)
	}
	message.WriteByte(0x00)
	message.ResetLength(PostgresMessageLengthOffsetStartup)
	return message.Bytes()
}

func SSLRequestMessage() []byte {
	message := NewMessageBuffer()
	message.WriteInt32(8)
	message.WriteInt32(SSLRequestCode)
	return message.Bytes()
}
