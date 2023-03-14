package main

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
func SSLResponseMessage(sslCode byte) (_ []byte, err error) {
	message := NewMessageBuffer()
	if err = message.WriteByte(sslCode); err != nil {
		return
	}
	return message.Bytes(), nil
}

/**
 * ReadyForQuery (B)
 *
 * Processing of the query string is complete.
 * A separate message is sent to indicate this because the query string might contain multiple SQL commands.
 * (CommandComplete marks the end of processing one SQL command, not the whole string.)
 * ReadyForQuery will always be sent, whether processing terminates successfully or with an error.
 */
func ReadyForQueryMessage() (_ []byte, err error) {
	message := NewMessageBuffer()
	if err = message.WriteByte(MessageTypeReadyForQuery); err != nil {
		return
	}
	if _, err = message.WriteInt32(5); err != nil {
		return
	}
	if err = message.WriteByte(TransactionStatusIdle); err != nil {
		return
	}
	return message.Bytes(), nil
}

/**
 * BackendKeyData (B)
 *
 * This message provides secret-key data that the frontend must save if it wants to be able to issue cancel requests later.
 *  The frontend should not respond to this message, but should continue listening for a ReadyForQuery message.
 */
func BackendKeyDataMessage(processID, secretKey int32) (_ []byte, err error) {
	message := NewMessageBuffer()
	if err = message.WriteByte(MessageTypeBackendKeyData); err != nil {
		return
	}
	if _, err = message.WriteInt32(12); err != nil {
		return
	}
	if _, err = message.WriteInt32(processID); err != nil {
		return
	}
	if _, err = message.WriteInt32(secretKey); err != nil {
		return
	}
	return message.Bytes(), nil
}

/**
 * ParameterStatus (B)
 *
 * This message informs the frontend about the current (initial) setting of backend parameters, such as client_encoding or DateStyle.
 * The frontend can ignore this message, or record the settings for its future use;
 * The frontend should not respond to this message, but should continue listening for a ReadyForQuery message.
 */
func ParameterStatusMessage(parameterName, parameterValue string) (_ []byte, err error) {
	message := NewMessageBuffer()
	if err = message.WriteByte(MessageTypeParameterStatus); err != nil {
		return
	}
	if _, err = message.WriteInt32(0); err != nil {
		return
	}
	if _, err = message.WriteString(parameterName); err != nil {
		return
	}
	if _, err = message.WriteString(parameterValue); err != nil {
		return
	}
	message.ResetLength(PostgresMessageLengthOffset)
	return message.Bytes(), nil
}

/**
 * AuthenticationOk (B)
 *
 * This message informs the frontend about the authentication exchange is successfully completed.
 */
func AuthenticationOkResponseMessage() (_ []byte, err error) {
	message := NewMessageBuffer()
	if err = message.WriteByte(MessageTypeAuthentication); err != nil {
		return
	}
	if _, err = message.WriteInt32(8); err != nil {
		return
	}
	if _, err = message.WriteInt32(AuthenticationOK); err != nil {
		return
	}
	return message.Bytes(), nil
}

/**
 * AuthenticationClearTextPassword (B)
 *
 * The frontend must now send a PasswordMessage containing the password in clear-text form.
 * If this is the correct password, the server responds with an AuthenticationOk, otherwise it responds with an ErrorResponse.
 */
func AuthenticationClearTextPasswordRequestMessage() (_ []byte, err error) {
	message := NewMessageBuffer()
	if err = message.WriteByte(MessageTypeAuthentication); err != nil {
		return
	}
	if _, err = message.WriteInt32(8); err != nil {
		return
	}
	if _, err = message.WriteInt32(AuthenticationClearTextPassword); err != nil {
		return
	}
	return message.Bytes(), nil
}
