package nex

// Eagle is the relay-server protocol used by the handful of Switch titles that
// hand gameplay off to a dedicated relay instead of Pia P2P: Tetris 99, Super
// Mario Bros. 35, PAC-MAN 99, and F-Zero 99. NEX matchmaking only forms the
// lobby; once it's ready, the game server starts (or reuses) an EagleServer for
// that gathering and pushes each joiner a wss:// URL + signed token via a
// NotificationEvent (see EagleHandoffMap and notification.go's Map field).
//
// Eagle itself does not understand any game logic: it's a bitstream-framed pub/
// sub relay between "nodes" (one per connected client, numbered 1..M-1, with 0
// reserved for "the server itself" and M/M+1 as broadcast targets), plus three
// generic per-session counter RPCs. All game-specific meaning lives in the RPC
// payloads (ids 16-255), which this server forwards opaquely.
//
// Wire format and behavior are ported from kinnay/NintendoClients' Eagle Protocol
// wiki page and kinnay/SMB35's source/eagle.py (AGPL-3.0, no code copied
// verbatim — reimplemented from the documented/read behavior), both MIT/AGPL
// reference material, not Nintendo's own code.
//
// The bitstream framing (bitStreamIn/bitStreamOut below) must match the retail
// client byte-for-byte. The handoff token (SignEagleToken/parseEagleToken) does
// NOT need to: the console only ever forwards it verbatim from the notification
// event to the Eagle login packet, never inspects its contents, so its shape is
// a private contract between this server's own signer and verifier.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lxzan/gws"
)

// ---------------------------------------------------------------------------
// Bit-level stream. Eagle packs fields MSB-first within each byte (matching
// kinnay/anynet's streams.BitStreamOut/In(">")) — distinct from stream.go's
// byte-level little-endian RMC framing, which is a different wire format.
// ---------------------------------------------------------------------------

type bitStreamOut struct {
	data   []byte
	bitPos uint8 // 0-7: next bit to set within the last byte of data
}

func (s *bitStreamOut) bit(v bool) {
	if s.bitPos == 0 {
		s.data = append(s.data, 0)
	}
	if v {
		s.data[len(s.data)-1] |= 1 << (7 - s.bitPos)
	}
	s.bitPos++
	if s.bitPos == 8 {
		s.bitPos = 0
	}
}

// bits writes the low n bits of value, most-significant bit first.
func (s *bitStreamOut) bits(value uint64, n int) {
	for i := n - 1; i >= 0; i-- {
		s.bit((value>>uint(i))&1 != 0)
	}
}

func (s *bitStreamOut) bytealign() { s.bitPos = 0 }

func (s *bitStreamOut) writeBytes(b []byte) {
	if s.bitPos == 0 {
		s.data = append(s.data, b...)
		return
	}
	for _, v := range b {
		s.bits(uint64(v), 8)
	}
}

func (s *bitStreamOut) ascii(str string) { s.writeBytes([]byte(str)) }
func (s *bitStreamOut) bytes() []byte    { return s.data }

type bitStreamIn struct {
	data   []byte
	pos    int
	bitPos uint8
	err    error
}

func newBitStreamIn(data []byte) *bitStreamIn { return &bitStreamIn{data: data} }

func (s *bitStreamIn) bit() bool {
	if s.err != nil || s.pos >= len(s.data) {
		s.err = io.ErrUnexpectedEOF
		return false
	}
	v := (s.data[s.pos]>>(7-s.bitPos))&1 != 0
	s.bitPos++
	if s.bitPos == 8 {
		s.bitPos = 0
		s.pos++
	}
	return v
}

// bits reads n bits, most-significant bit first.
func (s *bitStreamIn) bits(n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		var b uint64
		if s.bit() {
			b = 1
		}
		v = (v << 1) | b
	}
	return v
}

func (s *bitStreamIn) bytealign() {
	if s.bitPos != 0 {
		s.bitPos = 0
		s.pos++
	}
}

func (s *bitStreamIn) readBytes(n int) []byte {
	if s.err != nil || n < 0 {
		s.err = io.ErrUnexpectedEOF
		return nil
	}
	if s.bitPos == 0 {
		if s.pos+n > len(s.data) {
			s.err = io.ErrUnexpectedEOF
			return nil
		}
		b := s.data[s.pos : s.pos+n]
		s.pos += n
		return b
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(s.bits(8))
	}
	return out
}

func (s *bitStreamIn) ascii(n int) string { return string(s.readBytes(n)) }

// available returns the number of *whole bytes* remaining after the current
// (bit-aligned) position — only ever called right after bytealign(), matching
// every call site in the reference eagle.py.
func (s *bitStreamIn) available() int {
	if s.err != nil {
		return 0
	}
	return len(s.data) - s.pos
}

func (s *bitStreamIn) readAll() []byte { return s.readBytes(s.available()) }

// ---------------------------------------------------------------------------
// Packet types & client state
// ---------------------------------------------------------------------------

type eaglePacketType uint8

const (
	eagleAccepted     eaglePacketType = 0
	eagleLoginRequest eaglePacketType = 1
	eagleLoginResult  eaglePacketType = 2
	eagleClientReady  eaglePacketType = 3
	eaglePing         eaglePacketType = 4
	eaglePong         eaglePacketType = 5
	eagleNodeNotice   eaglePacketType = 8
	eagleDisconnected eaglePacketType = 9
	eagleRPCBase      eaglePacketType = 16
)

type eagleClientState uint8

const (
	eagleLoginPhase0 eagleClientState = iota
	eagleLoginPhase1
	eagleWaitReady
	eagleReady
	eagleClientDisconnected
)

// EagleConfig configures one Eagle deployment. The four known Eagle titles
// don't all agree on these constants — SMB35 and PAC-MAN 99 share NodeBits=11/
// MaxNodes=1024/ProtocolVersion=3; Tetris 99 uses NodeBits=9/MaxNodes=128/
// ProtocolVersion=2 — so nothing in this file is hardcoded to SMB35.
type EagleConfig struct {
	NodeBits        int    // N: bit width of a node id
	MaxNodes        uint32 // M: also the "broadcast except self" target id (M+1 = "broadcast including self")
	ProtocolVersion uint32 // eagle_version the login handshake must match
	AppVersion      uint64 // app_version the login handshake must match
	DDLHash         uint32 // ddl_hash the login handshake must match
	VersionString   string // client library version string the handshake must match

	SigningKey []byte        // HMAC-SHA256 key for handoff tokens
	ServerEnv  string        // token payload's server_env, e.g. "lp1"
	TokenTTL   time.Duration // handoff token validity window
}

// SMB35EagleConfig returns the constants Super Mario Bros. 35 uses, per
// kinnay/SMB35's source/eagle.py and source/main.py.
func SMB35EagleConfig(signingKey []byte) EagleConfig {
	return EagleConfig{
		NodeBits: 11, MaxNodes: 1024, ProtocolVersion: 3,
		AppVersion: 0, DDLHash: 0, VersionString: "2.0.4",
		SigningKey: signingKey, ServerEnv: "lp1", TokenTTL: 3 * time.Hour,
	}
}

// RandomEagleSigningKey returns a fresh random HMAC key for EagleConfig.SigningKey.
func RandomEagleSigningKey() []byte { return randomBytes(32) }

// ---------------------------------------------------------------------------
// Handoff token — created by the game server's matchmaking hook (see
// EagleHandoffMap), verified here at Eagle login. See the package comment for
// why this doesn't need to match retail's byte shape.
// ---------------------------------------------------------------------------

type smb35EagleTokenPayload struct {
	ExpiresAt string `json:"expires_at"`
	ServerEnv string `json:"server_env"`
	ServerID  string `json:"server_id"`
	UserID    string `json:"user_id"`
}

type smb35EagleToken struct {
	Payload   smb35EagleTokenPayload `json:"payload"`
	Signature string                 `json:"signature"`
	Version   int                    `json:"version"`
}

func signEagleTokenPayload(cfg EagleConfig, payload smb35EagleTokenPayload) string {
	payloadJSON, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, cfg.SigningKey)
	mac.Write(payloadJSON)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	tokJSON, _ := json.Marshal(smb35EagleToken{Payload: payload, Signature: sig, Version: 1})
	return base64.StdEncoding.EncodeToString(tokJSON)
}

// SignEagleToken creates the opaque token embedded in the Eagle-handoff
// NotificationEvent (see EagleHandoffMap) for one participant of one gathering.
func SignEagleToken(cfg EagleConfig, sessionID uint32, pid uint64) string {
	return signEagleTokenPayload(cfg, smb35EagleTokenPayload{
		ExpiresAt: strconv.FormatInt(time.Now().Add(cfg.TokenTTL).Unix(), 10),
		ServerEnv: cfg.ServerEnv,
		ServerID:  strconv.FormatUint(uint64(sessionID), 10),
		UserID:    strconv.FormatUint(pid, 10),
	})
}

// parseEagleToken validates a token created by SignEagleToken/signEagleTokenPayload
// and returns the user id it carries.
func parseEagleToken(tokenB64 string, cfg EagleConfig, sessionID uint32) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return "", false
	}
	var tok smb35EagleToken
	if err := json.Unmarshal(raw, &tok); err != nil || tok.Version != 1 {
		return "", false
	}
	payloadJSON, err := json.Marshal(tok.Payload)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, cfg.SigningKey)
	mac.Write(payloadJSON)
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(tok.Signature)) {
		return "", false
	}
	expiresAt, err := strconv.ParseInt(tok.Payload.ExpiresAt, 10, 64)
	if err != nil || time.Now().Unix() > expiresAt {
		return "", false
	}
	if tok.Payload.ServerEnv != cfg.ServerEnv {
		return "", false
	}
	if tok.Payload.ServerID != strconv.FormatUint(uint64(sessionID), 10) {
		return "", false
	}
	return tok.Payload.UserID, true
}

// EagleHandoffText builds the JSON payload {"url":..., "token":...} for a
// NotificationEvent.StrParam (event type 200000) that hands a joining
// participant off to wsURL's Eagle relay for the given gathering (session) id.
// Wire it into Matchmaking.OnParticipantJoined.
//
// This uses the plain StrParam field (StructureVersion 0 — the encoding
// confirmed working against real hardware) rather than the NEX 4.0+ Map
// extension kinnay/NintendoClients' notification.py documents for this event
// (EagleHandoffMap below, kept for reference/future use): a live test against
// a real SMB35 client showed the Map-encoded version never reaching the game
// at all (no Eagle connection attempt, from either the server's or the
// client's own log) — consistent with this package's existing note that the
// Map variant is "rejected outright" by at least one other already-verified
// title. Unverified either way pending another real-client test.
func EagleHandoffText(cfg EagleConfig, wsURL string, sessionID uint32, pid uint64) string {
	payload := struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}{URL: wsURL, Token: SignEagleToken(cfg, sessionID, pid)}
	b, _ := json.Marshal(payload)
	return string(b)
}

// EagleHandoffMap builds the {"url", "token"} pair for a NotificationEvent.Map
// (event type 200000) that hands a joining participant off to wsURL's Eagle
// relay for the given gathering (session) id. See EagleHandoffText's comment —
// kept for reference, not currently used by main.go.
func EagleHandoffMap(cfg EagleConfig, wsURL string, sessionID uint32, pid uint64) map[string]Variant {
	return map[string]Variant{
		"url":   {Type: VariantString, String: wsURL},
		"token": {Type: VariantString, String: SignEagleToken(cfg, sessionID, pid)},
	}
}

// ---------------------------------------------------------------------------
// EagleClient — one connected node.
// ---------------------------------------------------------------------------

// EagleClient is one connected node of an EagleServer session. Constructed only
// through EagleServer/EagleMgr; write/closeFn are injected so tests can drive
// the protocol logic without a real WebSocket (mirrors how Connection is built
// in endpoint.go/server.go).
type EagleClient struct {
	server  *EagleServer
	nodeID  uint32
	write   func([]byte) error
	closeFn func()

	mu    sync.Mutex // serializes this connection's packet processing
	state eagleClientState
	token strings.Builder
}

func nowMillis() uint64 { return uint64(time.Now().UnixMilli()) }

// HandlePacket processes one raw binary WebSocket frame from this node.
func (c *EagleClient) HandlePacket(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	in := newBitStreamIn(data)
	relayType := in.bits(2)
	payloadID := in.bits(8)
	sourceID := uint32(in.bits(c.server.cfg.NodeBits))
	_ = sourceID // the client's own claimed source id is untrusted; the server addresses relays by c.nodeID instead

	if relayType > 2 {
		fmt.Printf("[Eagle] session=%d node=%d invalid relay type %d\n", c.server.sessionID, c.nodeID, relayType)
		return
	}

	var relay []uint32
	switch relayType {
	case 1:
		relay = append(relay, uint32(in.bits(c.server.cfg.NodeBits)))
	case 2:
		for i := uint32(0); i < c.server.cfg.MaxNodes; i++ {
			if in.bit() {
				relay = append(relay, i)
			}
		}
	}
	in.bytealign()
	if in.err != nil {
		fmt.Printf("[Eagle] session=%d node=%d malformed packet: %v\n", c.server.sessionID, c.nodeID, in.err)
		return
	}

	switch {
	case payloadID == uint64(eagleLoginRequest):
		c.processLoginRequest(in)
	case payloadID == uint64(eagleClientReady):
		c.processClientReady()
	case payloadID == uint64(eaglePing):
		c.processPing(in)
	case payloadID == uint64(eagleDisconnected):
		c.state = eagleClientDisconnected
	case payloadID >= uint64(eagleRPCBase):
		c.processRPC(in, relay, uint8(payloadID))
	default:
		fmt.Printf("[Eagle] session=%d node=%d invalid payload id %d\n", c.server.sessionID, c.nodeID, payloadID)
	}
}

func (c *EagleClient) processLoginRequest(in *bitStreamIn) {
	phase := in.bits(7)
	lastFragment := in.bit()
	switch phase {
	case 0:
		c.processLoginHandshake(in)
	case 1:
		c.processLoginAuth(in, lastFragment)
	default:
		fmt.Printf("[Eagle] session=%d node=%d invalid login phase %d\n", c.server.sessionID, c.nodeID, phase)
	}
}

func (c *EagleClient) processLoginHandshake(in *bitStreamIn) {
	if c.state != eagleLoginPhase0 {
		return
	}
	connCheck := in.bits(8)
	eagleVersion := in.bits(32)
	appVersion := in.bits(64)
	ddlHash := in.bits(32)
	version := in.ascii(int(in.bits(8)))
	if in.err != nil {
		return
	}

	cfg := c.server.cfg
	if connCheck != 0 || uint32(eagleVersion) != cfg.ProtocolVersion || appVersion != cfg.AppVersion ||
		uint32(ddlHash) != cfg.DDLHash || version != cfg.VersionString {
		fmt.Printf("[Eagle] session=%d node=%d login handshake mismatch (check=%d version=%d/%d app=%d/%d ddl=%d/%d str=%q/%q)\n",
			c.server.sessionID, c.nodeID, connCheck, eagleVersion, cfg.ProtocolVersion, appVersion, cfg.AppVersion,
			ddlHash, cfg.DDLHash, version, cfg.VersionString)
		return
	}
	c.state = eagleLoginPhase1
}

func (c *EagleClient) processLoginAuth(in *bitStreamIn, lastFragment bool) {
	if c.state != eagleLoginPhase1 {
		return
	}
	frag := in.ascii(int(in.bits(8)))
	if in.err != nil {
		return
	}
	c.token.WriteString(frag)
	if !lastFragment {
		return
	}
	userID, ok := parseEagleToken(c.token.String(), c.server.cfg, c.server.sessionID)
	if !ok {
		fmt.Printf("[Eagle] session=%d node=%d token rejected\n", c.server.sessionID, c.nodeID)
		return
	}
	c.sendLoginResult(userID)
	c.state = eagleWaitReady
}

func (c *EagleClient) processClientReady() {
	if c.state != eagleWaitReady {
		return
	}
	c.state = eagleReady
	c.server.markReady(c)
}

func (c *EagleClient) processPing(in *bitStreamIn) {
	t := in.bits(64)
	if in.err != nil {
		return
	}
	c.sendPong(t)
}

func (c *EagleClient) processRPC(in *bitStreamIn, targets []uint32, rpcID uint8) {
	if c.state != eagleReady {
		return
	}
	_ = in.bits(64) // client-side send timestamp; the relay doesn't use it
	payload := in.readAll()
	if in.err != nil {
		return
	}
	c.server.relayRPC(c, targets, rpcID, payload)
}

func (c *EagleClient) sendAccepted() {
	out := &bitStreamOut{}
	out.bits(uint64(c.nodeID), 16)
	out.bits(nowMillis(), 64)
	c.send(eagleAccepted, out.bytes(), 0)
}

func (c *EagleClient) sendLoginResult(userID string) {
	out := &bitStreamOut{}
	out.bits(1, 32)
	out.bits(0, 8)
	out.bits(uint64(len(userID)), 16)
	out.ascii(userID)
	c.send(eagleLoginResult, out.bytes(), 0)
}

func (c *EagleClient) sendPong(clientTime uint64) {
	out := &bitStreamOut{}
	out.bits(nowMillis(), 64)
	out.bits(clientTime, 64)
	c.send(eaglePong, out.bytes(), 0)
}

func (c *EagleClient) sendNodeAdded(nodeID uint32) {
	out := &bitStreamOut{}
	out.bits(0, 8)
	out.bits(uint64(nodeID), 16)
	out.bits(nowMillis(), 64)
	c.send(eagleNodeNotice, out.bytes(), 0)
}

func (c *EagleClient) sendNodeRemoved(nodeID uint32) {
	out := &bitStreamOut{}
	out.bits(3, 8)
	out.bits(uint64(nodeID), 16)
	out.bits(nowMillis(), 64)
	c.send(eagleNodeNotice, out.bytes(), 0)
}

// sendAllNodes announces the full current roster (present is keyed by node id).
func (c *EagleClient) sendAllNodes(present map[uint32]*EagleClient) {
	out := &bitStreamOut{}
	out.bits(4, 8)
	for i := uint32(0); i < c.server.cfg.MaxNodes; i++ {
		_, ok := present[i]
		out.bit(ok)
	}
	out.bits(nowMillis(), 64)
	c.send(eagleNodeNotice, out.bytes(), 0)
}

func (c *EagleClient) sendRPC(sourceID uint32, rpcID uint8, payload []byte) {
	out := &bitStreamOut{}
	out.bits(nowMillis(), 64)
	out.writeBytes(payload)
	c.send(eaglePacketType(rpcID), out.bytes(), sourceID)
}

func (c *EagleClient) send(typ eaglePacketType, payload []byte, source uint32) {
	out := &bitStreamOut{}
	out.bits(0, 2)
	out.bits(uint64(typ), 8)
	out.bits(uint64(source), c.server.cfg.NodeBits)
	out.bytealign()
	out.writeBytes(payload)
	if err := c.write(out.bytes()); err != nil {
		c.server.removeNode(c)
	}
}

// ---------------------------------------------------------------------------
// EagleServer — one matchmake session's relay.
// ---------------------------------------------------------------------------

// EagleServer relays RPCs between the nodes of one matchmake gathering. Node id
// 0 addresses the server itself (the three counter RPCs below); M/M+1 broadcast
// to all ready nodes excluding/including the sender.
type EagleServer struct {
	cfg       EagleConfig
	sessionID uint32

	mu       sync.Mutex
	clients  map[uint32]*EagleClient // node id -> client, populated once READY (mirrors kinnay's EagleServer.clients)
	nextNode uint32
	counters [32]uint64
}

func newEagleServer(cfg EagleConfig, sessionID uint32) *EagleServer {
	return &EagleServer{cfg: cfg, sessionID: sessionID, clients: map[uint32]*EagleClient{}}
}

// newClient allocates the next node id for a freshly-connected socket, or
// returns nil if the session is full (node id would reach MaxNodes).
func (s *EagleServer) newClient(write func([]byte) error, closeFn func()) *EagleClient {
	s.mu.Lock()
	s.nextNode++
	id := s.nextNode
	full := id >= s.cfg.MaxNodes
	s.mu.Unlock()
	if full {
		return nil
	}
	return &EagleClient{server: s, nodeID: id, write: write, closeFn: closeFn, state: eagleLoginPhase0}
}

func (s *EagleServer) markReady(c *EagleClient) {
	s.mu.Lock()
	s.clients[c.nodeID] = c
	roster := make(map[uint32]*EagleClient, len(s.clients))
	others := make([]*EagleClient, 0, len(s.clients)-1)
	for id, other := range s.clients {
		roster[id] = other
		if other != c {
			others = append(others, other)
		}
	}
	s.mu.Unlock()

	c.sendAllNodes(roster)
	for _, other := range others {
		other.sendNodeAdded(c.nodeID)
	}
}

func (s *EagleServer) removeNode(c *EagleClient) {
	s.mu.Lock()
	_, existed := s.clients[c.nodeID]
	delete(s.clients, c.nodeID)
	remaining := make([]*EagleClient, 0, len(s.clients))
	for _, other := range s.clients {
		remaining = append(remaining, other)
	}
	s.mu.Unlock()
	if !existed {
		return
	}
	for _, other := range remaining {
		other.sendNodeRemoved(c.nodeID)
	}
}

// relayRPC resolves M/M+1 broadcast targets against the currently-ready roster
// and forwards the RPC to each destination; target 0 is the server itself.
func (s *EagleServer) relayRPC(source *EagleClient, targets []uint32, rpcID uint8, payload []byte) {
	s.mu.Lock()
	var resolved []uint32
	switch {
	case len(targets) == 1 && targets[0] == s.cfg.MaxNodes: // broadcast except sender
		for id, c := range s.clients {
			if c != source {
				resolved = append(resolved, id)
			}
		}
	case len(targets) == 1 && targets[0] == s.cfg.MaxNodes+1: // broadcast including sender
		for id := range s.clients {
			resolved = append(resolved, id)
		}
	default:
		resolved = targets
	}
	var dests []*EagleClient
	toServer := false
	for _, id := range resolved {
		if id == 0 {
			toServer = true
			continue
		}
		if c, ok := s.clients[id]; ok {
			dests = append(dests, c)
		}
	}
	s.mu.Unlock()

	if toServer {
		s.processServerRPC(source, rpcID, payload)
	}
	for _, c := range dests {
		c.sendRPC(source.nodeID, rpcID, payload)
	}
}

// processServerRPC implements the 3 generic per-session counters (32 slots)
// every Eagle deployment exposes, regardless of game.
func (s *EagleServer) processServerRPC(client *EagleClient, rpcID uint8, payload []byte) {
	in := newBitStreamIn(payload)
	index := in.bits(8)
	switch rpcID {
	case 18: // get_server_counter
		if in.err != nil || index >= 32 {
			return
		}
		s.mu.Lock()
		v := s.counters[index]
		s.mu.Unlock()
		s.sendCounter(client, uint8(index), v)
	case 17, 19: // set_server_counter, increase_server_counter
		value := in.bits(64)
		if in.err != nil || index >= 32 {
			return
		}
		s.mu.Lock()
		if rpcID == 17 {
			s.counters[index] = value
		} else {
			s.counters[index] += value
		}
		v := s.counters[index]
		s.mu.Unlock()
		s.sendCounter(client, uint8(index), v)
	default:
		fmt.Printf("[Eagle] session=%d unknown server RPC %d\n", s.sessionID, rpcID)
	}
}

func (s *EagleServer) sendCounter(client *EagleClient, index uint8, value uint64) {
	out := &bitStreamOut{}
	out.bits(uint64(index), 8)
	out.bits(value, 64)
	out.bits(0, 16) // reserved, per the reference implementation
	client.sendRPC(0, uint8(eagleRPCBase), out.bytes())
}

// close disconnects every node in the session (used when the matchmake
// gathering that owns it is torn down).
func (s *EagleServer) close() {
	s.mu.Lock()
	clients := make([]*EagleClient, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	for _, c := range clients {
		if c.closeFn != nil {
			c.closeFn()
		}
	}
}

// ---------------------------------------------------------------------------
// EagleMgr — hosts every active session's relay behind one WebSocket listener,
// routed by path "/<sessionID>". One EagleMgr per game server process.
// ---------------------------------------------------------------------------

type EagleMgr struct {
	cfg      EagleConfig
	upgrader *gws.Upgrader

	mu      sync.Mutex
	servers map[uint32]*EagleServer
}

// NewEagleMgr returns a manager for Eagle sessions using cfg. Note the
// WebSocket upgrader is intentionally NOT built with ParallelEnabled: Eagle's
// login handshake is a strict phase sequence (see eagleClientState), and
// per-connection frames must be processed in the order they arrive.
func NewEagleMgr(cfg EagleConfig) *EagleMgr {
	m := &EagleMgr{cfg: cfg, servers: map[uint32]*EagleServer{}}
	m.upgrader = gws.NewUpgrader(m, &gws.ServerOption{
		Recovery:        gws.Recovery,
		ReadBufferSize:  16 * 1024,
		WriteBufferSize: 16 * 1024,
	})
	return m
}

// Start returns the (created if needed) EagleServer for a matchmake gathering.
// Idempotent — safe to call once per join, matching kinnay's matchmaker.create()
// (start once) composed with matchmaker.join() (called once per participant,
// including the creator's own self-join).
func (m *EagleMgr) Start(sessionID uint32) *EagleServer {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.servers[sessionID]; ok {
		return s
	}
	s := newEagleServer(m.cfg, sessionID)
	m.servers[sessionID] = s
	return s
}

// Stop tears down a session's relay (all connected nodes are disconnected).
// Wire this to the gathering's teardown (unregister/end-of-round).
func (m *EagleMgr) Stop(sessionID uint32) {
	m.mu.Lock()
	s, ok := m.servers[sessionID]
	delete(m.servers, sessionID)
	m.mu.Unlock()
	if ok {
		s.close()
	}
}

const eagleServerSessionKey = "eagleServer"
const eagleClientSessionKey = "eagleClient"

// ServeHTTP routes "/<sessionID>" to that session's EagleServer and completes
// the WebSocket upgrade. Mount at the manager's listen port's root.
func (m *EagleMgr) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	m.mu.Lock()
	srv := m.servers[uint32(id)]
	m.mu.Unlock()
	if srv == nil {
		http.NotFound(w, r)
		return
	}

	socket, err := m.upgrader.Upgrade(w, r)
	if err != nil {
		fmt.Printf("[Eagle] upgrade failed session=%d: %v\n", id, err)
		return
	}
	// Stashed BEFORE starting the read loop's goroutine, so OnOpen (which runs
	// inside it) can already see which session this socket belongs to — gws only
	// hands OnOpen the raw *gws.Conn, not this request.
	socket.Session().Store(eagleServerSessionKey, srv)
	go socket.ReadLoop()
}

// ListenSecure serves every session this manager owns over secure WebSocket
// (wss://), same TLS setup as Server.ListenSecure in server.go (HTTP/2 disabled
// so the handshake stays plain HTTP/1.1 Upgrade).
func (m *EagleMgr) ListenSecure(port int, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      m,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// ListenInsecure serves over plain WebSocket (no TLS) — local test only.
func (m *EagleMgr) ListenInsecure(port int) error {
	return http.ListenAndServe(fmt.Sprintf(":%d", port), m)
}

// --- gws.Event implementation ---

func (m *EagleMgr) OnOpen(socket *gws.Conn) {
	v, ok := socket.Session().Load(eagleServerSessionKey)
	if !ok {
		return
	}
	srv := v.(*EagleServer)
	client := srv.newClient(
		func(b []byte) error { return socket.WriteMessage(gws.OpcodeBinary, b) },
		func() { _ = socket.WriteClose(1000, nil) },
	)
	if client == nil {
		_ = socket.WriteClose(1008, []byte("session full"))
		return
	}
	socket.Session().Store(eagleClientSessionKey, client)
	client.sendAccepted()
}

func (m *EagleMgr) OnClose(socket *gws.Conn, err error) {
	if v, ok := socket.Session().Load(eagleClientSessionKey); ok {
		client := v.(*EagleClient)
		client.server.removeNode(client)
	}
}

func (m *EagleMgr) OnPing(socket *gws.Conn, payload []byte) { _ = socket.WritePong(nil) }
func (m *EagleMgr) OnPong(socket *gws.Conn, payload []byte) {}

func (m *EagleMgr) OnMessage(socket *gws.Conn, message *gws.Message) {
	defer message.Close()
	if message.Opcode != gws.OpcodeBinary {
		return
	}
	v, ok := socket.Session().Load(eagleClientSessionKey)
	if !ok {
		return
	}
	client := v.(*EagleClient)
	data := append([]byte(nil), message.Bytes()...)
	client.HandlePacket(data)
}
