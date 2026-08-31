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

	framesOut     atomic.Uint64
	framesBatched atomic.Uint64
	drops         atomic.Uint64
	accepted      atomic.Uint64
}

// Stats is a snapshot of the hub's live counters (PROJECT.md §24).
type Stats struct {
	// Clients is the number of connections currently registered.
	Clients int
	// Accepted is the total number of connections ever registered.
	Accepted uint64
	// FramesOut is the total number of frames written to individual clients.
	FramesOut uint64
	// FramesBatched is the total number of batched payloads handed to
	// Broadcast — one per pump flush, independent of the client count.
	FramesBatched uint64
	// Drops is the total number of clients dropped for a full send queue.
	Drops uint64
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

// Broadcast queues payload for every client as one batched frame. Slow clients
// are dropped. The batched-frame counter advances once per call, whether or not
// a client is connected.
func (h *Hub) Broadcast(payload []byte) {
	h.framesBatched.Add(1)

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

// Stats reports a snapshot of the live counters.
func (h *Hub) Stats() Stats {
	h.mu.RLock()
	n := len(h.clients)
	h.mu.RUnlock()
	return Stats{
		Clients:       n,
		Accepted:      h.accepted.Load(),
		FramesOut:     h.framesOut.Load(),
		FramesBatched: h.framesBatched.Load(),
		Drops:         h.drops.Load(),
	}
}
