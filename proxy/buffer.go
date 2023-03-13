package main

import (
	"bytes"
	"encoding/binary"
)

type PostgresMessageBuffer struct {
	buffer *bytes.Buffer
}

func NewMessageBuffer() *PostgresMessageBuffer {
	return &PostgresMessageBuffer{
		buffer: bytes.NewBuffer([]byte{}),
	}
}

func (message *PostgresMessageBuffer) WriteByte(value byte) error {
	return message.buffer.WriteByte(value)
}

func (message *PostgresMessageBuffer) WriteBytes(value []byte) (int, error) {
	return message.buffer.Write(value)
}

func (message *PostgresMessageBuffer) WriteInt32(value int32) (int, error) {
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(value))
	return message.WriteBytes(x)
}

func (message *PostgresMessageBuffer) WriteString(value string) (int, error) {
	return message.buffer.WriteString((value + "\000"))
}

func (message *PostgresMessageBuffer) ResetLength(offset int) {
	b := message.buffer.Bytes()
	s := b[offset:]
	binary.BigEndian.PutUint32(s, uint32(len(s)))
}

func (message *PostgresMessageBuffer) Bytes() []byte {
	return message.buffer.Bytes()
}
