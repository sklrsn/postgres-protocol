package postgres

/**
 * Message Formats
 * https://www.postgresql.org/docs/current/protocol-message-formats.html
 *
 * Backend (B)
 */

/**
 * SSLResponse (B)
 *
 * To initiate an SSL-encrypted connection, the frontend initially sends an SSLRequest message rather than a StartupMessage.
 * The server then responds with a single byte containing S or N, indicating that it is willing or unwilling to perform SSL, respectively
 */
func SSLResponseMessage(sslCode byte) []byte {
	message := NewMessageBuffer()
	message.WriteByte(sslCode)
	return message.Bytes()
}

/**
 * ReadyForQuery (B)
 *
 * Processing of the query string is complete.
 * A separate message is sent to indicate this because the query string might contain multiple SQL commands.
 * (CommandComplete marks the end of processing one SQL command, not the whole string.)
 * ReadyForQuery will always be sent, whether processing terminates successfully or with an error.
 */
func ReadyForQueryMessage() []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeReadyForQuery)
	message.WriteInt32(5)
	message.WriteByte(TransactionStatusIdle)
	return message.Bytes()
}

/**
 * BackendKeyData (B)
 *
 * This message provides secret-key data that the frontend must save if it wants to be able to issue cancel requests later.
 *  The frontend should not respond to this message, but should continue listening for a ReadyForQuery message.
 */
func BackendKeyDataMessage(processID, secretKey int32) []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeBackendKeyData)
	message.WriteInt32(12)
	message.WriteInt32(processID)
	message.WriteInt32(secretKey)
	return message.Bytes()
}

/**
 * ParameterStatus (B)
 *
 * This message informs the frontend about the current (initial) setting of backend parameters, such as client_encoding or DateStyle.
 * The frontend can ignore this message, or record the settings for its future use;
 * The frontend should not respond to this message, but should continue listening for a ReadyForQuery message.
 */
func ParameterStatusMessage(parameterName, parameterValue string) []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeParameterStatus)
	message.WriteInt32(0)
	message.WriteString(parameterName)
	message.WriteString(parameterValue)
	message.ResetLength(PostgresMessageLengthOffset)
	return message.Bytes()
}

/**
 * AuthenticationOk (B)
 *
 * This message informs the frontend about the authentication exchange is successfully completed.
 */
func AuthenticationOkResponseMessage() []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeAuthentication)
	message.WriteInt32(8)
	message.WriteInt32(AuthenticationOK)
	return message.Bytes()
}

/**
 * AuthenticationClearTextPassword (B)
 *
 * The frontend must now send a PasswordMessage containing the password in clear-text form.
 * If this is the correct password, the server responds with an AuthenticationOk, otherwise it responds with an ErrorResponse.
 */
func AuthenticationClearTextPasswordRequestMessage() []byte {
	message := NewMessageBuffer()
	message.WriteByte(MessageTypeAuthentication)
	message.WriteInt32(8)
	message.WriteInt32(AuthenticationClearTextPassword)
	return message.Bytes()
}
