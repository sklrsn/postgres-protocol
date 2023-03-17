package main

import (
	"encoding/hex"
	"log"
	"sync"
)

type ChannelRecorder struct {
	C         chan []byte
	closeOnce sync.Once
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
		case data, ok := <-cr.C:
			if !ok {
				return
			}
			log.Printf("postgres-proxy: transferred %v bytes", len(data))
			log.Printf("postgres-proxy: msg=%v", hex.Dump(data))
		}
	}
}

func (cr ChannelRecorder) Close() {
	cr.closeOnce.Do(func() {
		close(cr.C)
	})
}
