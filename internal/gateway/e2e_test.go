package gateway_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/agent"
	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/gateway"
	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wire"
)

// upperEngine is a stand-in wire engine: it forwards client->upstream verbatim and upper-cases the
// upstream->client direction. That stands in for "the agent transformed the bytes" so the test can
// assert the full client -> gateway -> tunnel -> agent -> upstream path (both directions) works.
type upperEngine struct{}

func (upperEngine) Name() string { return "upper" }

func (upperEngine) Proxy(_ context.Context, client, upstream net.Conn, _ mask.Masker, _ wire.Recorder) error {
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(upstream, client); errc <- e }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				if _, werr := client.Write(bytes.ToUpper(buf[:n])); werr != nil {
					errc <- werr
					return
				}
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	err := <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	return err
}

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// taggedEngine discards whatever the client sends and always replies with a fixed tag — used to
// unambiguously tell which of two agents actually served a given client connection (unlike
// upperEngine, whose output would be identical regardless of which org handled the request).
type taggedEngine struct{ tag string }

func (e taggedEngine) Name() string { return "tagged" }

func (e taggedEngine) Proxy(_ context.Context, client, upstream net.Conn, _ mask.Masker, _ wire.Recorder) error {
	go io.Copy(io.Discard, client) //nolint:errcheck // client->upstream direction is irrelevant to this test double
	_, err := client.Write([]byte(e.tag))
	_ = upstream.Close()
	_ = client.Close()
	return err
}

// mtlsAgentPipe builds an in-memory (agent-side, gateway-side) connection pair, both wrapped in TLS
// with a fresh self-signed CA issuing the agent's client cert for (tenant, agentID) — agent
// registration requires a verified mTLS client certificate unconditionally (no bearer-token
// fallback, see internal/gateway/gateway.go's ServeAgent), so every e2e test that needs an agent to
// actually register must dial in over a connection like this one instead of a bare net.Pipe.
func mtlsAgentPipe(t *testing.T, tenant, agentID string) (agentSide, gwSide net.Conn) {
	t.Helper()
	ca := newTestCA(t)
	serverCert := ca.issueServerCert(t)
	clientCert := ca.issueClientCert(t, tenant, agentID)

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	clientTLSCfg := &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool, ServerName: "localhost"}

	agentRaw, gwRaw := net.Pipe()
	return tls.Client(agentRaw, clientTLSCfg), tls.Server(gwRaw, serverTLSCfg)
}

// stubTargetResolver is a TargetResolver test double: it resolves target names against a canned
// map, replacing what the agent used to announce at registration.
type stubTargetResolver map[string]tunnel.Target

func (s stubTargetResolver) Resolve(_ context.Context, _, target string) (tunnel.Target, error) {
	t, ok := s[target]
	if !ok {
		return tunnel.Target{}, gateway.ErrTargetNotFound
	}
	return t, nil
}

func TestEndToEndTunnelRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New(silent())
	rec := &recordingStore{}
	g.SetStore(rec)
	g.SetTargetResolver(stubTargetResolver{
		"db": {Name: "db", Addr: "upstream:0", DBType: "upper", ResourceRoleID: "role-1", ActorEmail: "owner@example.com"},
	})

	// Agent <-> gateway over an in-memory, mTLS-wrapped pipe (agent registration requires a
	// verified client cert unconditionally — see mtlsAgentPipe).
	agentLocal, agentGW := mtlsAgentPipe(t, "org-1", "a1")
	go func() { _ = g.ServeAgent(agentGW) }()

	cfg := config.Agent{
		Mode: config.ModeTunnel,
		// Deliberately no AgentID/OrgID set here — the cert supplies identity (see mtlsAgentPipe).
	}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()

	// Wait for the agent to register under its org.
	if !waitForOrgAgent(g, "org-1", 2*time.Second) {
		t.Fatal("agent did not register in time")
	}

	// Native client <-> gateway over an in-memory pipe.
	clientGW, client := net.Pipe()
	go func() { _ = g.ServeClient(clientGW, "org-1", "db") }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != "PING" {
		t.Fatalf("got %q want PING (round trip through the tunnel)", got)
	}

	// Close the client so the relay ends and the session is recorded.
	_ = client.Close()
	if !rec.waitEnded(2 * time.Second) {
		t.Fatal("session end was not recorded")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.started.Target != "db" || rec.started.DBType != "upper" || rec.started.OrgID != "org-1" {
		t.Fatalf("start record wrong: %+v", rec.started)
	}
	// Attribution from the resolver's binding must reach the control plane so the session is owned
	// (not recorded unattributed).
	if rec.started.ResourceRoleID != "role-1" || rec.started.ActorEmail != "owner@example.com" {
		t.Fatalf("attribution not relayed: role=%q actor=%q", rec.started.ResourceRoleID, rec.started.ActorEmail)
	}
	if rec.ended.BytesUp == 0 || rec.ended.BytesDown == 0 {
		t.Fatalf("expected non-zero byte counts, got up=%d down=%d", rec.ended.BytesUp, rec.ended.BytesDown)
	}
	if rec.endedID != "rec-1" {
		t.Fatalf("end called with id %q, want rec-1", rec.endedID)
	}
}

type recordingStore struct {
	mu      sync.Mutex
	started gateway.SessionRecord
	ended   gateway.SessionResult
	endedID string
	done    bool
}

func (s *recordingStore) SessionStarted(_ context.Context, rec gateway.SessionRecord) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = rec
	return "rec-1", nil
}

func (s *recordingStore) SessionEnded(_ context.Context, id string, res gateway.SessionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endedID = id
	s.ended = res
	s.done = true
	return nil
}

func (s *recordingStore) SessionTranscript(_ context.Context, _ string, _ gateway.TranscriptChunks) error {
	return nil
}

func (s *recordingStore) waitEnded(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		done := s.done
		s.mu.Unlock()
		if done {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// pgStartupBytes builds a Postgres StartupMessage carrying a user parameter (test helper).
func pgStartupBytes(user string) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 196608) // protocol version 3.0
	for _, kv := range []string{"user", user, "database", "prod"} {
		body = append(body, []byte(kv)...)
		body = append(body, 0)
	}
	body = append(body, 0)
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	copy(out[4:], body)
	return out
}

// TestRelayAttributesByLoginUsername proves the gateway sniffs the DB login off the relayed
// handshake and reports it at close, so the control plane can attribute the session to its owner.
func TestRelayAttributesByLoginUsername(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New(silent())
	rec := &recordingStore{}
	g.SetStore(rec)
	g.SetTargetResolver(stubTargetResolver{
		"pg": {Name: "pg", Addr: "upstream:0", DBType: "postgres", ResourceRoleID: "role-1"},
	})

	agentLocal, agentGW := mtlsAgentPipe(t, "org-1", "a1")
	go func() { _ = g.ServeAgent(agentGW) }()

	cfg := config.Agent{
		Mode: config.ModeTunnel,
	}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()
	if !waitForOrgAgent(g, "org-1", 2*time.Second) {
		t.Fatal("agent did not register in time")
	}

	clientGW, client := net.Pipe()
	go func() { _ = g.ServeClient(clientGW, "org-1", "pg") }()

	if _, err := client.Write(pgStartupBytes("alice")); err != nil {
		t.Fatal(err)
	}
	// Drain whatever the echo upstream sends back so the relay isn't blocked, then close.
	go func() { _, _ = io.Copy(io.Discard, client) }()
	time.Sleep(50 * time.Millisecond)
	_ = client.Close()

	if !rec.waitEnded(2 * time.Second) {
		t.Fatal("session end was not recorded")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.started.ResourceRoleID != "role-1" {
		t.Fatalf("resource role not relayed: %+v", rec.started)
	}
	if rec.ended.DBUsername != "alice" {
		t.Fatalf("db username not sniffed/relayed: %q", rec.ended.DBUsername)
	}
}

func TestServeClientNoAgent(t *testing.T) {
	g := gateway.New(silent())
	_, client := net.Pipe()
	if err := g.ServeClient(client, "org-1", "missing"); err != gateway.ErrNoAgent {
		t.Fatalf("want ErrNoAgent, got %v", err)
	}
}

func TestServeClientRejectsWhenResolverFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New(silent())
	rec := &recordingStore{}
	g.SetStore(rec)
	g.SetTargetResolver(stubTargetResolver{}) // resolves nothing -> ErrTargetNotFound for any target

	agentLocal, agentGW := mtlsAgentPipe(t, "org-1", "a1")
	go func() { _ = g.ServeAgent(agentGW) }()

	cfg := config.Agent{Mode: config.ModeTunnel}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()
	if !waitForOrgAgent(g, "org-1", 2*time.Second) {
		t.Fatal("agent did not register in time")
	}

	clientGW, client := net.Pipe()
	errc := make(chan error, 1)
	go func() { errc <- g.ServeClient(clientGW, "org-1", "db") }()

	// The client should see the connection close with no bytes relayed, since the resolver failed
	// before any tunnel stream was opened.
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected client connection to close without relaying any bytes")
	}
	if err := <-errc; !errors.Is(err, gateway.ErrTargetNotFound) {
		t.Fatalf("want ErrTargetNotFound, got %v", err)
	}
}

func TestServeAgentRejectsMissingOrgIDWhenResolverIsLive(t *testing.T) {
	g := gateway.New(silent())
	g.SetTargetResolver(stubTargetResolver{"db": {Name: "db", Addr: "x:0", DBType: "upper"}})
	// Empty tenant in the cert itself, so reg.OrgID resolves to "" post-mTLS-verification and the
	// missing-organization_id check (not the mTLS check) is what this test actually exercises.
	local, gw := mtlsAgentPipe(t, "", "a1")
	go func() { _ = g.ServeAgent(gw) }()

	cfg := config.Agent{
		Mode:    config.ModeTunnel,
		AgentID: "a1",
	}
	err := agent.ServeTunnelConn(context.Background(), local, cfg, agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}, silent())
	if err == nil {
		t.Fatal("expected registration rejection when a live TargetResolver requires organization_id")
	}
}

func TestServeClientRejectsMissingOrgID(t *testing.T) {
	g := gateway.New(silent())
	g.SetTargetResolver(stubTargetResolver{"db": {Name: "db", Addr: "x:0", DBType: "upper"}})

	clientGW, client := net.Pipe()
	err := g.ServeClient(clientGW, "", "db")
	if !errors.Is(err, gateway.ErrMissingOrgID) {
		t.Fatalf("want ErrMissingOrgID, got %v", err)
	}
	_ = client.Close()
}

func TestServeClientRejectsRateLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New(silent())
	g.SetConnRateLimiter(gateway.NewConnRateLimiter(1, 0))
	g.SetTargetResolver(stubTargetResolver{"db": {Name: "db", Addr: "upstream:0", DBType: "upper"}})
	rec := &recordingStore{}
	g.SetStore(rec)

	agentLocal, agentGW := mtlsAgentPipe(t, "org-1", "a1")
	go func() { _ = g.ServeAgent(agentGW) }()

	cfg := config.Agent{
		Mode: config.ModeTunnel,
	}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()

	if !waitForOrgAgent(g, "org-1", 2*time.Second) {
		t.Fatal("agent did not register in time")
	}

	clientGW1, client1 := net.Pipe()
	go func() { _ = g.ServeClient(clientGW1, "org-1", "db") }()
	time.Sleep(20 * time.Millisecond)
	_ = client1.Close()

	clientGW2, client2 := net.Pipe()
	err := g.ServeClient(clientGW2, "org-1", "db")
	_ = client2.Close()
	if !errors.Is(err, gateway.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
}

// TestServeClientRejectsOrgConnLimitReached is the regression test for the concurrent-connection
// ceiling: unlike TestServeClientRejectsRateLimit above (which throttles the *rate* of new
// connections and lets the first one close before trying again), this keeps the first connection
// open throughout — proving the org is blocked by its *standing* connection count, not by how fast
// it opens new ones. Without OrgConnLimiter, an org could hold arbitrarily many connections open
// simultaneously (rate limiting alone never catches this), exhausting gateway/agent goroutines and
// file descriptors at every other org's expense.
func TestServeClientRejectsOrgConnLimitReached(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New(silent())
	g.SetOrgConnLimiter(gateway.NewOrgConnLimiter(1))
	g.SetTargetResolver(stubTargetResolver{"db": {Name: "db", Addr: "upstream:0", DBType: "upper"}})
	rec := &recordingStore{}
	g.SetStore(rec)

	agentLocal, agentGW := mtlsAgentPipe(t, "org-1", "a1")
	go func() { _ = g.ServeAgent(agentGW) }()

	cfg := config.Agent{
		Mode: config.ModeTunnel,
	}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()

	if !waitForOrgAgent(g, "org-1", 2*time.Second) {
		t.Fatal("agent did not register in time")
	}

	clientGW1, client1 := net.Pipe()
	firstDone := make(chan error, 1)
	go func() { firstDone <- g.ServeClient(clientGW1, "org-1", "db") }()
	time.Sleep(20 * time.Millisecond) // let the first ServeClient acquire its slot and start relaying

	// The first connection is still open — a second must be rejected on the standing-count ceiling,
	// not a rate limiter (none is configured on this Gateway).
	clientGW2, client2 := net.Pipe()
	err := g.ServeClient(clientGW2, "org-1", "db")
	_ = client2.Close()
	if !errors.Is(err, gateway.ErrOrgConnLimitReached) {
		t.Fatalf("want ErrOrgConnLimitReached while the first connection is still open, got %v", err)
	}

	// Closing the first connection must free its slot — a third attempt should now succeed.
	_ = client1.Close()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first ServeClient did not return after its client closed")
	}

	clientGW3, client3 := net.Pipe()
	go func() { _ = g.ServeClient(clientGW3, "org-1", "db") }()
	time.Sleep(20 * time.Millisecond)
	if _, err := client3.Write([]byte("ping")); err != nil {
		t.Fatalf("expected the third connection to be admitted after the slot freed up, write failed: %v", err)
	}
	_ = client3.Close()
}

// TestServeAgentRejectsRateLimit is the regression test for SetAgentConnLimiter: before it
// existed, nothing in this package limited how many times the agent listener's mTLS handshake
// could be probed per client IP — an attacker (or a misconfigured agent stuck retrying) could
// attempt registration at whatever rate raw TCP handshakes allow. Both attempts drive a real
// agent.ServeTunnelConn client over a verified mTLS pipe (rather than a bare net.Pipe end with
// nothing reading it — ServeAgent's rejection path writes a control message back, which blocks
// forever on an unbuffered net.Pipe with no reader on the other side).
func TestServeAgentRejectsRateLimit(t *testing.T) {
	g := gateway.New(silent())
	g.SetAgentConnLimiter(gateway.NewConnRateLimiter(1, 0))

	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}

	// First attempt consumes the one-per-minute slot; net.Pipe's RemoteAddr() is the constant
	// string "pipe" for every pipe, so this and the second attempt look like the same client IP to
	// the limiter. A short-lived context is enough — the point is just to let ServeAgent's rate
	// check run and the registration complete before tearing down.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel1()
	local1, gw1 := mtlsAgentPipe(t, "org-1", "a1")
	go func() { _ = g.ServeAgent(gw1) }()
	_ = agent.ServeTunnelConn(ctx1, local1, config.Agent{Mode: config.ModeTunnel, AgentID: "a1"}, deps, silent())

	local2, gw2 := mtlsAgentPipe(t, "org-1", "a2")
	go func() { _ = g.ServeAgent(gw2) }()
	err := agent.ServeTunnelConn(context.Background(), local2, config.Agent{Mode: config.ModeTunnel, AgentID: "a2"}, deps, silent())
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected the second registration to be rejected by the rate limiter, got %v", err)
	}
}

// echoDialer returns a fresh in-memory upstream that echoes whatever is written to it.
func echoDialer(_ context.Context, _, _ string) (net.Conn, error) {
	c, s := net.Pipe()
	go func() { _, _ = io.Copy(s, s) }()
	return c, nil
}

func waitForOrgAgent(g *gateway.Gateway, orgID string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, o := range g.RegisteredOrgs() {
			if o == orgID {
				return true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// captureClientHelloBytes returns the raw bytes a real tls.Client handshake attempt writes for the
// given SNI server name — a genuine ClientHello record, not hand-built. Used to drive
// SetSNIOrgResolution tests without needing a live TLS responder: the handshake attempt is left to
// fail/timeout (nothing ever replies), which is fine — only the bytes it already wrote matter.
func captureClientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	capturedCh := make(chan []byte, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			capturedCh <- nil
			return
		}
		defer raw.Close()
		buf := make([]byte, 8192)
		_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := raw.Read(buf)
		capturedCh <- buf[:n]
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		client := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec // test, no live responder
		_ = client.Handshake()                                                                    // expected to fail — nothing replies; only the write matters
	}()

	select {
	case b := <-capturedCh:
		if len(b) == 0 {
			t.Fatal("captured empty ClientHello")
		}
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timed out capturing ClientHello")
	}
	return nil
}

// TestListenClientsLogsSNIResolvedOrgOnRejection is the regression test for the log-consistency fix
// found debugging a real "target not found" rejection live: logRejectedClient's "rejected" line
// already logged the SNI-resolved org, but ListenClients' own "ended" line logged the listener's
// stale static org instead (it never learned the per-connection override), so the two log lines for
// the very same rejected connection disagreed — confusing during exactly the kind of cross-log
// debugging this was found by. ListenClients must now log the same effective (SNI-resolved) org in
// both.
// syncBuffer wraps bytes.Buffer with a mutex so it's safe as a slog handler's writer when the test
// goroutine polls String() concurrently with ListenClients' own goroutine writing a log line —
// bytes.Buffer itself has no internal synchronization, so unguarded concurrent Write/String use is
// a real data race (caught by -race), not just a hypothetical one.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestListenClientsLogsSNIResolvedOrgOnRejection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logBuf syncBuffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	g := gateway.New(logger)
	g.SetSNIOrgResolution(true)
	g.SetTargetResolver(stubTargetResolver{}) // resolves nothing -> ErrTargetNotFound, same as the live bug

	// org-2 has a registered agent (so rejection happens at target-resolve, past the SNI override
	// point) — org-1 is the listener's static config, standing in for the shared/pinned org a real
	// client's SNI would be routed away from.
	agentLocal, agentGW := mtlsAgentPipe(t, "org-2", "agent-org-2")
	go func() { _ = g.ServeAgent(agentGW) }()
	cfg := config.Agent{Mode: config.ModeTunnel}
	deps := agent.Deps{Dial: echoDialer, Engine: func(string) (wire.Engine, error) { return taggedEngine{tag: "x"}, nil }, Masker: mask.Noop{}}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()
	if !waitForOrgAgent(g, "org-2", 2*time.Second) {
		t.Fatal("agent for org-2 did not register in time")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = g.ListenClients(ctx, ln, "org-1", "db") }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(captureClientHelloBytes(t, "org-2.wire.test")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logBuf.String(), "client relay for org=") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// slog's TextHandler Go-quotes the whole msg value (it contains literal '"' characters from the
	// %q-formatted org/target), so the captured bytes contain escaped \" sequences, not bare "chars.
	logged := logBuf.String()
	if !strings.Contains(logged, `client relay for org=\"org-2\"`) {
		t.Fatalf("expected the \"ended\" log line to use the SNI-resolved org-2, got: %s", logged)
	}
	if strings.Contains(logged, `client relay for org=\"org-1\"`) {
		t.Fatalf("\"ended\" log line still uses the stale static org-1 instead of the SNI-resolved org: %s", logged)
	}
}

// TestServeClientSNIOrgResolutionRoutesToTheRightOrg is the regression test for the
// docs/design/kubernetes-access-broker.md §11.5 fix: one shared listener, statically configured
// for org-1, must route a client presenting `org-2.wire.test` SNI to org-2's agent instead —
// without SetSNIOrgResolution, the exact same client would go to the statically pinned org-1.
func TestServeClientSNIOrgResolutionRoutesToTheRightOrg(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New(silent())
	g.SetSNIOrgResolution(true)
	g.SetTargetResolver(stubTargetResolver{
		"db": {Name: "db", Addr: "upstream:0", DBType: "upper", ResourceRoleID: "role-1", ActorEmail: "owner@example.com"},
	})

	tags := map[string]string{"org-1": "FROM-ORG-1", "org-2": "FROM-ORG-2"}
	for _, org := range []string{"org-1", "org-2"} {
		agentLocal, agentGW := mtlsAgentPipe(t, org, "agent-"+org)
		go func() { _ = g.ServeAgent(agentGW) }()
		cfg := config.Agent{Mode: config.ModeTunnel}
		tag := tags[org]
		deps := agent.Deps{
			Dial:   echoDialer,
			Engine: func(string) (wire.Engine, error) { return taggedEngine{tag: tag}, nil },
			Masker: mask.Noop{},
		}
		go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()
		if !waitForOrgAgent(g, org, 2*time.Second) {
			t.Fatalf("agent for %s did not register in time", org)
		}
	}

	clientHello := captureClientHelloBytes(t, "org-2.wire.test")

	clientGW, client := net.Pipe()
	// Listener is statically configured for org-1 — proves the override, not just "org-2 happens
	// to be the default."
	go func() { _ = g.ServeClient(clientGW, "org-1", "db") }()

	if _, err := client.Write(clientHello); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(tags["org-2"]))
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(client, buf)
	if err != nil {
		t.Fatalf("read relayed bytes: %v", err)
	}
	if got := string(buf[:n]); got != tags["org-2"] {
		t.Fatalf("got %q, want %q — client's org-2.wire.test SNI should route to org-2's agent, not the statically pinned org-1", got, tags["org-2"])
	}
}

// TestServeClientSNIOrgResolutionFallsBackWithoutSNI confirms a client that never sends SNI at all
// (e.g. connects with a bare IP, or SNI resolution is simply not in play) still gets the listener's
// statically configured org — SetSNIOrgResolution must never make an SNI-less client second-class.
func TestServeClientSNIOrgResolutionFallsBackWithoutSNI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New(silent())
	g.SetSNIOrgResolution(true)
	g.SetTargetResolver(stubTargetResolver{
		"db": {Name: "db", Addr: "upstream:0", DBType: "upper", ResourceRoleID: "role-1", ActorEmail: "owner@example.com"},
	})

	agentLocal, agentGW := mtlsAgentPipe(t, "org-1", "agent-org-1")
	go func() { _ = g.ServeAgent(agentGW) }()
	cfg := config.Agent{Mode: config.ModeTunnel}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()
	if !waitForOrgAgent(g, "org-1", 2*time.Second) {
		t.Fatal("agent did not register in time")
	}

	clientGW, client := net.Pipe()
	go func() { _ = g.ServeClient(clientGW, "org-1", "db") }()

	if _, err := client.Write([]byte("plaintext, no tls at all")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read relayed bytes: %v", err)
	}
	if !bytes.Equal(buf[:n], bytes.ToUpper([]byte("plaintext, no tls at all"))) {
		t.Fatalf("got %q, want the org-1 agent's uppercased echo — SNI-less client must still reach the static org", buf[:n])
	}
}
