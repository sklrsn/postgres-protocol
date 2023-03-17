package main

import (
	"encoding/hex"
	"log"
)

type ChannelRecorder struct {
	C chan []byte
}

func (cr ChannelRecorder) Write(data []byte) (int, error) {
	go func() {
		cr.C <- data
	}()

	return len(data), nil
}

func (cr ChannelRecorder) Watch() {
	for {
		select {
		case data := <-cr.C:
			log.Printf("postgres-proxy: transferred %v bytes", len(data))
			log.Printf("postgres-proxy: msg=%v", hex.Dump(data))
		}
	}
}
