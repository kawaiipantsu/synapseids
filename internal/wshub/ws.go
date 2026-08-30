// Package wshub is a dependency-free RFC 6455 WebSocket server for the daemon's
// single live channel. It implements just what SynapseIDS needs: an HTTP upgrade,
// server->client text frames, and enough client-frame handling to notice a
// disconnect and answer pings. The fan-out Hub gives every client a bounded send
// queue and drops — never blocks on — a client that cannot keep up
// (PROJECT.md §18, §22).
package wshub

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ErrNotWebSocket is returned by Upgrade when the request is not a valid
// RFC 6455 handshake.
var ErrNotWebSocket = errors.New("wshub: not a websocket upgrade request")

// Conn is a single upgraded connection.
type Conn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
	once sync.Once
	done chan struct{}
}

// Upgrade completes the handshake and hijacks the connection.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !headerContainsToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, ErrNotWebSocket
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, ErrNotWebSocket
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("wshub: response writer does not support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // RFC 6455 mandates SHA-1 here
	accept := base64.StdEncoding.EncodeToString(sum[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	c := &Conn{conn: conn, br: rw.Reader, done: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

// Done is closed when the connection is torn down.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Close sends a best-effort close frame and shuts the socket.
func (c *Conn) Close() error {
	c.once.Do(func() {
		c.wmu.Lock()
		_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.conn.Write([]byte{0x88, 0x00}) // opcode 8, no payload
		c.wmu.Unlock()
		_ = c.conn.Close()
		close(c.done)
	})
	return nil
}

// WriteText writes one unmasked text frame. Payloads up to 2^63 are supported;
// SynapseIDS batches stay well under 64 KiB.
func (c *Conn) WriteText(p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	var hdr [10]byte
	hdr[0] = 0x81 // FIN + opcode 1 (text)
	n := 2
	switch {
	case len(p) < 126:
		hdr[1] = byte(len(p))
	case len(p) < 1<<16:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(p)))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(len(p)))
		n = 10
	}
	if _, err := c.conn.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := c.conn.Write(p)
	return err
}

// readLoop consumes client frames so a disconnect is noticed promptly and pings
// are answered. Application text from the client is discarded — the live channel
// is server-to-client only in Phase 1.
func (c *Conn) readLoop() {
	defer func() { _ = c.Close() }()
	for {
		op, payload, err := c.readFrame()
		if err != nil {
			return
		}
		switch op {
		case 0x8: // close
			return
		case 0x9: // ping -> pong
			c.wmu.Lock()
			_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			frame := append([]byte{0x8A, byte(len(payload))}, payload...)
			_, werr := c.conn.Write(frame)
			c.wmu.Unlock()
			if werr != nil {
				return
			}
		default:
			// text/binary/pong/continuation — ignore
		}
	}
}

func (c *Conn) readFrame() (opcode byte, payload []byte, err error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	var h [2]byte
	if _, err = io.ReadFull(c.br, h[:]); err != nil {
		return 0, nil, err
	}
	opcode = h[0] & 0x0f
	masked := h[1]&0x80 != 0
	ln := int(h[1] & 0x7f)
	switch ln {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		v := binary.BigEndian.Uint64(ext[:])
		if v > 1<<20 { // 1 MiB cap on inbound control/data from a client
			return 0, nil, errors.New("wshub: client frame too large")
		}
		ln = int(v)
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	buf := make([]byte, ln)
	if _, err = io.ReadFull(c.br, buf); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range buf {
			buf[i] ^= mask[i&3]
		}
	}
	return opcode, buf, nil
}

func headerContainsToken(h http.Header, name, token string) bool {
	for _, v := range h[http.CanonicalHeaderKey(name)] {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}
