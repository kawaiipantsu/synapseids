package wshub

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// wsClient does a minimal RFC 6455 client handshake against addr and returns the
// live connection plus its buffered reader.
func wsClient(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	req := "GET /api/v1/stream HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("handshake status %q err %v", status, err)
	}
	want := base64.StdEncoding.EncodeToString(func() []byte { s := sha1.Sum([]byte(key + wsGUID)); return s[:] }())
	var sawAccept bool
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept:") {
			if !strings.Contains(line, want) {
				t.Fatalf("bad accept header: %q want %q", line, want)
			}
			sawAccept = true
		}
	}
	if !sawAccept {
		t.Fatal("no Sec-WebSocket-Accept header")
	}
	return c, br
}

func readServerFrame(t *testing.T, br *bufio.Reader) (opcode byte, payload []byte) {
	t.Helper()
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		t.Fatal(err)
	}
	opcode = h[0] & 0x0f
	ln := int(h[1] & 0x7f)
	switch ln {
	case 126:
		ext := make([]byte, 2)
		mustRead(t, br, ext)
		ln = int(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		mustRead(t, br, ext)
		ln = int(binary.BigEndian.Uint64(ext))
	}
	payload = make([]byte, ln)
	mustRead(t, br, payload)
	return opcode, payload
}

func mustRead(t *testing.T, r io.Reader, buf []byte) {
	t.Helper()
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
}

func writeMasked(c net.Conn, opcode byte, payload []byte) {
	hdr := []byte{0x80 | opcode, 0x80 | byte(len(payload))}
	mask := []byte{1, 2, 3, 4}
	hdr = append(hdr, mask...)
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	_, _ = c.Write(append(hdr, masked...))
}

func TestUpgradeAndTextFrame(t *testing.T) {
	got := make(chan *Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		got <- conn
		_ = conn.WriteText([]byte(`[{"type":"hello"}]`))
		<-conn.Done()
	}))
	defer srv.Close()

	c, br := wsClient(t, strings.TrimPrefix(srv.URL, "http://"))
	defer func() { _ = c.Close() }()

	op, payload := readServerFrame(t, br)
	if op != 0x1 || string(payload) != `[{"type":"hello"}]` {
		t.Fatalf("frame op=%d payload=%q", op, payload)
	}

	serverConn := <-got
	writeMasked(c, 0x8, nil) // client close
	select {
	case <-serverConn.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("server did not notice client close")
	}
}

func TestUpgradeRejectsPlainHTTP(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/stream", nil)
	if _, err := Upgrade(rr, req); err == nil {
		t.Fatal("plain GET should not upgrade")
	}
}

func TestHubBroadcastAndSlowClientDrop(t *testing.T) {
	hub := NewHub(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r)
		if err != nil {
			return
		}
		hub.Add(conn)
	}))
	defer srv.Close()

	c, br := wsClient(t, strings.TrimPrefix(srv.URL, "http://"))
	defer func() { _ = c.Close() }()

	// Read the first frame so the client is alive, then stop reading.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n, _, _, _ := hub.Stats(); n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	hub.Broadcast([]byte("[1]"))
	readServerFrame(t, br)

	// Flood without reading: the bounded queue fills and the client is dropped.
	dropDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(dropDeadline) {
		for i := 0; i < 20; i++ {
			hub.Broadcast([]byte("[2]"))
		}
		if _, _, _, drops := hub.Stats(); drops > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("slow client was never dropped")
}
