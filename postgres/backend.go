package postgres

/**
 * Message Formats
 * https://www.postgresql.org/docs/current/protocol-message-formats.html
 *
 * (B)
 */

func SSLResponseMessage(sslCode byte) []byte {
	message := NewMessageBuffer()
	message.WriteByte(sslCode)
	return message.Bytes()
}

func ReadyForQueryMessage() []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeReadyForQuery)
	message.WriteInt32(5)
	message.WriteByte(TransactionStatusIdle)
	return message.Bytes()
}

func BackendKeyDataMessage(processID, secretKey int32) []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeBackendKeyData)
	message.WriteInt32(12)
	message.WriteInt32(processID)
	message.WriteInt32(secretKey)
	return message.Bytes()
}

func ParameterStatusMessage(parameterName, parameterValue string) []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeParameterStatus)
	message.WriteInt32(0)
	message.WriteString(parameterName)
	message.WriteString(parameterValue)
	message.ResetLength(PostgresMessageLengthOffset)
	return message.Bytes()
}

func AuthenticationOkResponseMessage() []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeAuthentication)
	message.WriteInt32(8)
	message.WriteInt32(AuthenticationOK)
	return message.Bytes()
}

func AuthenticationClearTextPasswordRequestMessage() []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeAuthentication)
	message.WriteInt32(8)
	message.WriteInt32(AuthenticationClearTextPassword)
	return message.Bytes()
}
