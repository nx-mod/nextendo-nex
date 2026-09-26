package nex

import (
	"sync"
	"testing"
	"time"
)

func testEagleConfig() EagleConfig {
	return SMB35EagleConfig([]byte("test-signing-key"))
}

// --- bit stream ---

func TestBitStreamRoundTrip(t *testing.T) {
	out := &bitStreamOut{}
	out.bits(0, 2)
	out.bits(200, 8)
	out.bits(1234, 11)
	out.bit(true)
	out.bit(false)
	out.bytealign()
	out.ascii("hi")

	in := newBitStreamIn(out.bytes())
	if v := in.bits(2); v != 0 {
		t.Fatalf("relay type: got %d want 0", v)
	}
	if v := in.bits(8); v != 200 {
		t.Fatalf("u8 field: got %d want 200", v)
	}
	if v := in.bits(11); v != 1234 {
		t.Fatalf("11-bit field: got %d want 1234", v)
	}
	if !in.bit() || in.bit() {
		t.Fatalf("bit flags not round-tripped")
	}
	in.bytealign()
	if s := in.ascii(2); s != "hi" {
		t.Fatalf("ascii: got %q want \"hi\"", s)
	}
	if in.err != nil {
		t.Fatalf("unexpected stream error: %v", in.err)
	}
}

func TestBitStreamUnderflow(t *testing.T) {
	in := newBitStreamIn([]byte{0xFF})
	_ = in.bits(8)
	_ = in.bits(8) // past the end
	if in.err == nil {
		t.Fatal("expected underflow error")
	}
}

// --- token ---

func TestEagleTokenRoundTrip(t *testing.T) {
	cfg := testEagleConfig()
	tok := SignEagleToken(cfg, 42, 0x123456789)
	userID, ok := parseEagleToken(tok, cfg, 42)
	if !ok {
		t.Fatal("valid token rejected")
	}
	if want := "4886718345"; userID != want { // strconv.FormatUint(0x123456789, 10)
		t.Fatalf("user id: got %q want %q", userID, want)
	}
}

func TestEagleTokenWrongSession(t *testing.T) {
	cfg := testEagleConfig()
	tok := SignEagleToken(cfg, 42, 7)
	if _, ok := parseEagleToken(tok, cfg, 43); ok {
		t.Fatal("token for a different session was accepted")
	}
}

func TestEagleTokenTampered(t *testing.T) {
	cfg := testEagleConfig()
	tok := SignEagleToken(cfg, 42, 7)
	tampered := tok[:len(tok)-4] + "AAAA"
	if _, ok := parseEagleToken(tampered, cfg, 42); ok {
		t.Fatal("tampered token was accepted")
	}
}

func TestEagleTokenExpired(t *testing.T) {
	cfg := testEagleConfig()
	cfg.TokenTTL = -time.Minute // already expired
	tok := SignEagleToken(cfg, 42, 7)
	if _, ok := parseEagleToken(tok, cfg, 42); ok {
		t.Fatal("expired token was accepted")
	}
}

func TestEagleTokenWrongKeyRejected(t *testing.T) {
	cfg := testEagleConfig()
	tok := SignEagleToken(cfg, 42, 7)
	other := cfg
	other.SigningKey = []byte("different-key")
	if _, ok := parseEagleToken(tok, other, 42); ok {
		t.Fatal("token verified against the wrong signing key")
	}
}

// --- relay server (no real sockets: EagleClient.write is a captured closure,
// same pattern the core uses for Connection in server.go) ---

type fakeEagleSink struct {
	mu       sync.Mutex
	frames   [][]byte
	closed   bool
	writeErr error
}

func (f *fakeEagleSink) write(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	cp := append([]byte(nil), b...)
	f.frames = append(f.frames, cp)
	return nil
}

func (f *fakeEagleSink) close() { f.mu.Lock(); f.closed = true; f.mu.Unlock() }

func (f *fakeEagleSink) last() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.frames) == 0 {
		return nil
	}
	return f.frames[len(f.frames)-1]
}

func (f *fakeEagleSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames)
}

// readyClient drives a fresh EagleServer node through the full login handshake
// (handshake -> auth -> ready) using real wire-format packets, and returns the
// client plus its sink so tests can inspect what the server sent it.
func readyClient(t *testing.T, s *EagleServer, pid uint64) (*EagleClient, *fakeEagleSink) {
	t.Helper()
	sink := &fakeEagleSink{}
	c := s.newClient(sink.write, sink.close)
	if c == nil {
		t.Fatal("session unexpectedly full")
	}
	c.sendAccepted()

	tok := SignEagleToken(s.cfg, s.sessionID, pid)

	// LOGIN_REQUEST phase 0: handshake.
	out := &bitStreamOut{}
	out.bits(0, 2)
	out.bits(uint64(eagleLoginRequest), 8)
	out.bits(0, s.cfg.NodeBits)
	out.bytealign()
	out.bits(0, 7) // phase 0
	out.bit(true)  // last fragment (irrelevant for phase 0)
	out.bits(0, 8) // connection_check
	out.bits(uint64(s.cfg.ProtocolVersion), 32)
	out.bits(s.cfg.AppVersion, 64)
	out.bits(uint64(s.cfg.DDLHash), 32)
	out.bits(uint64(len(s.cfg.VersionString)), 8)
	out.ascii(s.cfg.VersionString)
	c.HandlePacket(out.bytes())
	if c.state != eagleLoginPhase1 {
		t.Fatalf("handshake: state = %d, want eagleLoginPhase1", c.state)
	}

	// LOGIN_REQUEST phase 1: auth, single fragment.
	out = &bitStreamOut{}
	out.bits(0, 2)
	out.bits(uint64(eagleLoginRequest), 8)
	out.bits(0, s.cfg.NodeBits)
	out.bytealign()
	out.bits(1, 7) // phase 1
	out.bit(true)  // last fragment
	out.bits(uint64(len(tok)), 8)
	out.ascii(tok)
	c.HandlePacket(out.bytes())
	if c.state != eagleWaitReady {
		t.Fatalf("auth: state = %d, want eagleWaitReady", c.state)
	}

	// CLIENT_READY.
	out = &bitStreamOut{}
	out.bits(0, 2)
	out.bits(uint64(eagleClientReady), 8)
	out.bits(0, s.cfg.NodeBits)
	out.bytealign()
	c.HandlePacket(out.bytes())
	if c.state != eagleReady {
		t.Fatalf("ready: state = %d, want eagleReady", c.state)
	}
	return c, sink
}

func sendRPCPacket(t *testing.T, s *EagleServer, c *EagleClient, relayType int, target uint32, rpcID uint8, payload []byte) {
	t.Helper()
	out := &bitStreamOut{}
	out.bits(uint64(relayType), 2)
	out.bits(uint64(rpcID), 8)
	out.bits(uint64(c.nodeID), s.cfg.NodeBits)
	switch relayType {
	case 1:
		out.bits(uint64(target), s.cfg.NodeBits)
	case 2:
		for i := uint32(0); i < s.cfg.MaxNodes; i++ {
			out.bit(i == target)
		}
	}
	out.bytealign()
	out.bits(nowMillis(), 64) // client timestamp
	out.writeBytes(payload)
	c.HandlePacket(out.bytes())
}

func TestEagleLoginHandshake(t *testing.T) {
	cfg := testEagleConfig()
	s := newEagleServer(cfg, 100)
	c, sink := readyClient(t, s, 555)
	if c.nodeID != 1 {
		t.Fatalf("first node id = %d, want 1", c.nodeID)
	}
	// Accepted, login result, and the "all nodes" roster on ready = 3 frames.
	if got := sink.count(); got != 3 {
		t.Fatalf("frames sent to node during login: got %d want 3", got)
	}
}

func TestEagleLoginRejectsBadToken(t *testing.T) {
	cfg := testEagleConfig()
	s := newEagleServer(cfg, 100)
	sink := &fakeEagleSink{}
	c := s.newClient(sink.write, sink.close)

	out := &bitStreamOut{}
	out.bits(0, 2)
	out.bits(uint64(eagleLoginRequest), 8)
	out.bits(0, s.cfg.NodeBits)
	out.bytealign()
	out.bits(0, 7)
	out.bit(true)
	out.bits(0, 8)
	out.bits(uint64(s.cfg.ProtocolVersion), 32)
	out.bits(s.cfg.AppVersion, 64)
	out.bits(uint64(s.cfg.DDLHash), 32)
	out.bits(uint64(len(s.cfg.VersionString)), 8)
	out.ascii(s.cfg.VersionString)
	c.HandlePacket(out.bytes())

	bad := "not-a-real-token"
	out = &bitStreamOut{}
	out.bits(0, 2)
	out.bits(uint64(eagleLoginRequest), 8)
	out.bits(0, s.cfg.NodeBits)
	out.bytealign()
	out.bits(1, 7)
	out.bit(true)
	out.bits(uint64(len(bad)), 8)
	out.ascii(bad)
	c.HandlePacket(out.bytes())

	if c.state != eagleLoginPhase1 {
		t.Fatalf("state advanced past auth despite a rejected token: %d", c.state)
	}
}

func TestEagleNodeAddedAndRemoved(t *testing.T) {
	cfg := testEagleConfig()
	s := newEagleServer(cfg, 200)
	c1, sink1 := readyClient(t, s, 1)
	countAfterFirst := sink1.count()

	_, sink2 := readyClient(t, s, 2)
	// c1 should have been told about node 2 joining.
	if got := sink1.count(); got != countAfterFirst+1 {
		t.Fatalf("node1 frames after node2 joins: got %d want %d", got, countAfterFirst+1)
	}

	s.removeNode(c1)
	// sink2's last frame should be a NODE_NOTICE removing node 1.
	last := sink2.last()
	in := newBitStreamIn(last)
	_ = in.bits(2)
	typ := in.bits(8)
	_ = in.bits(s.cfg.NodeBits)
	in.bytealign()
	if typ != uint64(eagleNodeNotice) {
		t.Fatalf("expected a NODE_NOTICE after removal, got type %d", typ)
	}
	subtype := in.bits(8)
	removedID := in.bits(16)
	if subtype != 3 || removedID != uint64(c1.nodeID) {
		t.Fatalf("node-removed notice: subtype=%d removedID=%d, want subtype=3 removedID=%d", subtype, removedID, c1.nodeID)
	}
}

func TestEagleRelayDirectTarget(t *testing.T) {
	cfg := testEagleConfig()
	s := newEagleServer(cfg, 300)
	c1, _ := readyClient(t, s, 1)
	c2, sink2 := readyClient(t, s, 2)
	before := sink2.count()

	sendRPCPacket(t, s, c1, 1, c2.nodeID, 20, []byte("hello"))

	if got := sink2.count(); got != before+1 {
		t.Fatalf("node2 frames after direct RPC: got %d want %d", got, before+1)
	}
	in := newBitStreamIn(sink2.last())
	_ = in.bits(2)
	typ := in.bits(8)
	src := in.bits(s.cfg.NodeBits)
	in.bytealign()
	_ = in.bits(64) // server timestamp
	payload := in.readAll()
	if typ != 20 || src != uint64(c1.nodeID) || string(payload) != "hello" {
		t.Fatalf("relayed RPC mismatch: type=%d src=%d payload=%q", typ, src, payload)
	}
}

func TestEagleRelayBroadcastExcludingSender(t *testing.T) {
	cfg := testEagleConfig()
	s := newEagleServer(cfg, 301)
	c1, sink1 := readyClient(t, s, 1)
	_, sink2 := readyClient(t, s, 2)
	_, sink3 := readyClient(t, s, 3)
	b1, b2, b3 := sink1.count(), sink2.count(), sink3.count()

	// Broadcast target M ("everyone but the sender") is expressed on the wire as
	// relay_type 1 (a single explicit target) whose value happens to equal M.
	sendRPCPacket(t, s, c1, 1, cfg.MaxNodes, 21, []byte("x"))

	if sink1.count() != b1 {
		t.Fatalf("sender received its own broadcast-excluding-self RPC: got %d frames, want %d", sink1.count(), b1)
	}
	if sink2.count() != b2+1 || sink3.count() != b3+1 {
		t.Fatalf("broadcast-excluding-self didn't reach both other nodes: node2=%d(want %d) node3=%d(want %d)",
			sink2.count(), b2+1, sink3.count(), b3+1)
	}
}

func TestEagleRelayBroadcastIncludingSender(t *testing.T) {
	cfg := testEagleConfig()
	s := newEagleServer(cfg, 302)
	c1, sink1 := readyClient(t, s, 1)
	_, sink2 := readyClient(t, s, 2)
	b1, b2 := sink1.count(), sink2.count()

	sendRPCPacket(t, s, c1, 1, cfg.MaxNodes+1, 22, []byte("y"))

	if sink1.count() != b1+1 {
		t.Fatalf("sender did not receive broadcast-including-self RPC: got %d frames, want %d", sink1.count(), b1+1)
	}
	if sink2.count() != b2+1 {
		t.Fatalf("other node did not receive broadcast-including-self RPC: got %d frames, want %d", sink2.count(), b2+1)
	}
}

func TestEagleServerCounters(t *testing.T) {
	cfg := testEagleConfig()
	s := newEagleServer(cfg, 400)
	c1, sink1 := readyClient(t, s, 1)
	before := sink1.count()

	// set_server_counter(index=3, value=10) targeted at node 0 (the server).
	payload := &bitStreamOut{}
	payload.bits(3, 8)
	payload.bits(10, 64)
	sendRPCPacket(t, s, c1, 1, 0, 17, payload.bytes())

	if got := sink1.count(); got != before+1 {
		t.Fatalf("expected exactly one counter response, got %d new frames", got-before)
	}
	in := newBitStreamIn(sink1.last())
	_ = in.bits(2)
	typ := in.bits(8)
	_ = in.bits(s.cfg.NodeBits)
	in.bytealign()
	_ = in.bits(64) // server timestamp
	idx := in.bits(8)
	val := in.bits(64)
	if typ != 16 || idx != 3 || val != 10 {
		t.Fatalf("counter response mismatch: type=%d idx=%d val=%d", typ, idx, val)
	}

	// increase_server_counter(index=3, value=5) -> expect 15.
	payload = &bitStreamOut{}
	payload.bits(3, 8)
	payload.bits(5, 64)
	sendRPCPacket(t, s, c1, 1, 0, 19, payload.bytes())
	in = newBitStreamIn(sink1.last())
	_ = in.bits(2)
	_ = in.bits(8)
	_ = in.bits(s.cfg.NodeBits)
	in.bytealign()
	_ = in.bits(64)
	_ = in.bits(8)
	val = in.bits(64)
	if val != 15 {
		t.Fatalf("counter after increase: got %d want 15", val)
	}
}

func TestEagleSessionFull(t *testing.T) {
	cfg := testEagleConfig()
	cfg.MaxNodes = 2 // only node id 1 fits
	s := newEagleServer(cfg, 500)
	sink := &fakeEagleSink{}
	if c := s.newClient(sink.write, sink.close); c == nil {
		t.Fatal("first node should be accepted")
	}
	sink2 := &fakeEagleSink{}
	if c := s.newClient(sink2.write, sink2.close); c != nil {
		t.Fatal("second node should have been refused (session full)")
	}
}

func TestEagleMgrStartIsIdempotent(t *testing.T) {
	m := NewEagleMgr(testEagleConfig())
	s1 := m.Start(7)
	s2 := m.Start(7)
	if s1 != s2 {
		t.Fatal("Start returned a different server for the same session id")
	}
}
