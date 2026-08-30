package wshub

import (
	"sync"
	"sync/atomic"
)

// Hub fans a byte payload out to every connected client. Each client has a
// bounded send queue; if it is full when a broadcast arrives, the client is
// dropped and counted rather than blocking the caller (PROJECT.md §22).
type Hub struct {
	queueSize int

	mu      sync.RWMutex
	clients map[*client]struct{}

	framesOut atomic.Uint64
	drops     atomic.Uint64
	accepted  atomic.Uint64
}

type client struct {
	conn *Conn
	send chan []byte
}

// NewHub returns a Hub whose per-client queue holds queueSize payloads (min 1).
func NewHub(queueSize int) *Hub {
	if queueSize < 1 {
		queueSize = 1
	}
	return &Hub{queueSize: queueSize, clients: make(map[*client]struct{})}
}

// Add registers an upgraded connection and starts its writer. It returns when
// the connection is closed by either side.
func (h *Hub) Add(conn *Conn) {
	cl := &client{conn: conn, send: make(chan []byte, h.queueSize)}
	h.mu.Lock()
	h.clients[cl] = struct{}{}
	h.mu.Unlock()
	h.accepted.Add(1)

	defer func() {
		h.mu.Lock()
		delete(h.clients, cl)
		h.mu.Unlock()
		_ = conn.Close()
	}()

	for {
		select {
		case <-conn.Done():
			return
		case p := <-cl.send:
			if err := conn.WriteText(p); err != nil {
				return
			}
			h.framesOut.Add(1)
		}
	}
}

// Broadcast queues payload for every client. Slow clients are dropped.
func (h *Hub) Broadcast(payload []byte) {
	h.mu.RLock()
	victims := make([]*client, 0)
	for cl := range h.clients {
		select {
		case cl.send <- payload:
		default:
			victims = append(victims, cl)
		}
	}
	h.mu.RUnlock()

	for _, cl := range victims {
		h.drops.Add(1)
		_ = cl.conn.Close()
	}
}

// Stats reports live counters.
func (h *Hub) Stats() (clients int, accepted, framesOut, drops uint64) {
	h.mu.RLock()
	n := len(h.clients)
	h.mu.RUnlock()
	return n, h.accepted.Load(), h.framesOut.Load(), h.drops.Load()
}
