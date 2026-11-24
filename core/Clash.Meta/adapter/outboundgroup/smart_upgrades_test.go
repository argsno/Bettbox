package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/sockstat"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// hangingProxy blocks DialContext until ctx is done, simulating a black-holed node.
type hangingProxy struct {
	*fakeProxy
	wait time.Duration
}

func (p *hangingProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	p.dialCalls++
	if p.wait > 0 {
		timer := time.NewTimer(p.wait)
		defer timer.Stop()
		select {
		case <-timer.C:
			if p.dialErr != nil {
				return nil, p.dialErr
			}
			return &fakeConn{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// earlyFailConn simulates an EarlyConn (NeedHandshake=true) whose first Write fails.
type earlyFailConn struct {
	fakeConn
	writeErr   error
	writeDelay time.Duration
}

func (c *earlyFailConn) NeedHandshake() bool { return true }

func (c *earlyFailConn) Write(b []byte) (int, error) {
	if c.writeDelay > 0 {
		time.Sleep(c.writeDelay)
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}

type earlyProxy struct {
	*fakeProxy
	conn *earlyFailConn
}

func (p *earlyProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	p.dialCalls++
	return p.conn, nil
}

func TestSmartBlackHoleSubTimeoutFallsBackAndPenalizes(t *testing.T) {
	blackhole := &hangingProxy{fakeProxy: newFakeProxy("Blackhole", 50)}
	healthy := newFakeProxy("Healthy", 200)
	healthy.dialConn = &fakeConn{}
	s := newTestSmartWithProxies(blackhole, healthy)
	s.service = "openai" // disable hedge to test sequential sub-timeout fallback deterministically
	s.lastProbe = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := s.DialContext(ctx, &C.Metadata{Host: "example.com"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected fallback to healthy candidate, got error: %v", err)
	}
	_ = conn.Close()

	if blackhole.dialCalls != 1 || healthy.dialCalls != 1 {
		t.Fatalf("expected 1 call each, got blackhole=%d healthy=%d", blackhole.dialCalls, healthy.dialCalls)
	}
	if elapsed >= 1400*time.Millisecond {
		t.Fatalf("fallback took too long (%v); sub-timeout did not bound first attempt", elapsed)
	}
	s.mu.RLock()
	st := s.states["Blackhole"]
	s.mu.RUnlock()
	if st == nil || st.failStreak != 1 {
		t.Fatalf("black-hole timeout must penalize node, got %+v", st)
	}
}

func TestSmartNeedHandshakeFirstWriteFailureReportsFailure(t *testing.T) {
	p := &earlyProxy{
		fakeProxy: newFakeProxy("EarlyBad", 50),
		conn:      &earlyFailConn{writeErr: errors.New("tls handshake failed")},
	}
	backup := newFakeProxy("Backup", 200)
	s := newTestSmartWithProxies(p, backup)
	meta := &C.Metadata{Host: "early.example.com"}

	// Prime cache first.
	s.orderedCandidates(meta, false)
	s.mu.RLock()
	genBefore := s.rankGen
	s.mu.RUnlock()

	conn, err := s.DialContext(context.Background(), meta)
	if err != nil {
		t.Fatalf("dial returned unexpected error: %v", err)
	}
	if _, werr := conn.Write([]byte("ClientHello")); werr == nil {
		t.Fatalf("expected first write handshake error")
	}
	_ = conn.Close()

	s.mu.RLock()
	st := s.states["EarlyBad"]
	genAfter := s.rankGen
	s.mu.RUnlock()
	if st == nil || st.failStreak != 1 {
		t.Fatalf("NeedHandshake first-write failure must record node failure, got %+v", st)
	}
	if genAfter <= genBefore {
		t.Fatalf("NeedHandshake first-write failure must invalidate rank cache")
	}
}

func TestSmartServiceProbeRollingWindowSkipsBlockedLowLatencyRegion(t *testing.T) {
	// 15 fast HK nodes (all blocked) + 5 slower JP/US nodes (unprobed).
	var proxies []C.Proxy
	for i := 0; i < 15; i++ {
		proxies = append(proxies, newFakeProxy(fmt.Sprintf("HK-%02d", i), uint16(30+i)))
	}
	for i := 0; i < 5; i++ {
		proxies = append(proxies, newFakeProxy(fmt.Sprintf("US-%02d", i), uint16(150+i*10)))
	}
	s := newTestSmartWithProxies(proxies...)
	s.service = "openai"
	now := time.Now()

	s.mu.Lock()
	for i := 0; i < 15; i++ {
		s.verdicts[fmt.Sprintf("HK-%02d", i)] = serviceVerdict{
			at:      now,
			known:   true,
			blocked: true,
			region:  "HK",
		}
	}
	selected, offered := s.selectServiceProbeMembersLocked(s.Proxies(), now)
	s.mu.Unlock()

	if offered != 5 {
		t.Fatalf("expected 5 usable candidates past blocked HK nodes, got %d", offered)
	}
	if len(selected) != 5 {
		t.Fatalf("expected all 5 US nodes to be selected for probing, got %v", names(selected))
	}
	for _, p := range selected {
		if !strings.HasPrefix(p.Name(), "US-") {
			t.Fatalf("blocked HK node must not be re-selected while fresh: %s", p.Name())
		}
	}
}

func TestSmartObserveLossDecaysBeforeSmoothing(t *testing.T) {
	now := time.Now()
	st := &smartPolicyState{}
	st.observeLoss(0.5, now) // capped at 2000ms
	if st.lossPenalty != smartLossPenaltyMax {
		t.Fatalf("want max loss penalty %v, got %v", smartLossPenaltyMax, st.lossPenalty)
	}

	// Two hours later (~12 half-lives), a clean 0% loss connection closes.
	// Old penalty must decay first rather than resurrecting to 1000ms.
	later := now.Add(2 * time.Hour)
	st.observeLoss(0.0, later)
	if st.lossPenalty > 1.0 {
		t.Fatalf("stale loss penalty must decay before smoothing, got %v", st.lossPenalty)
	}
}

func TestSmartLatencyOutlierWinsorizationAndSampleCap(t *testing.T) {
	now := time.Now()
	st := &smartPolicyState{}
	st.observeLatency(50, now)
	// A 4000ms spike (below smartSampleCap) must be Winsorized and blended conservatively.
	st.observeLatency(4000, now.Add(time.Second))
	if st.score > 300 {
		t.Fatalf("single spike must be Winsorized instead of ruining a 50ms node, got %v", st.score)
	}

	// An LLM-like 12s TTFB must be dropped from latency scoring while still recording site success.
	s := newTestSmart()
	meta := &C.Metadata{Host: "api.openai.com"}
	s.reportLatency("Fast", meta, 60)
	before := s.states["Fast"].score
	s.reportLatency("Fast", meta, 12000)
	if s.states["Fast"].score != before {
		t.Fatalf("TTFB above smartSampleCap must not alter score: before=%v after=%v", before, s.states["Fast"].score)
	}
}

func TestSmartSocketRTTAndJitterPenalty(t *testing.T) {
	s := newTestSmart()
	s.reportRetransmit("Jittery", sockstat.TCPStats{
		RTT:    80 * time.Millisecond,
		RTTVar: 130 * time.Millisecond,
	}, true)

	st := s.states["Jittery"]
	if st == nil {
		t.Fatalf("expected state to be created from socket RTT stats")
	}
	if math.Abs(st.score-80) > 0.1 {
		t.Fatalf("expected socket SRTT to seed unknown score at 80ms, got %v", st.score)
	}
	wantJitter := (130.0 - smartJitterBaseMs) * smartJitterWeight
	if math.Abs(st.jitterPenalty-wantJitter) > 0.1 {
		t.Fatalf("expected jitter penalty %v, got %v", wantJitter, st.jitterPenalty)
	}
}

func TestSmartConnReplaceableAfterFirstWriteAndRead(t *testing.T) {
	s := newTestSmart()
	conn := &fakeConn{readData: []byte("pong")}
	sc := newSmartConn(conn, s, "A", &C.Metadata{Host: "fast.example.com"}, time.Now(), 0).(*smartConn)

	if sc.WriterReplaceable() || sc.ReaderReplaceable() {
		t.Fatalf("fresh smartConn must not be replaceable before first write/read")
	}
	if _, err := sc.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if !sc.WriterReplaceable() || sc.ReaderReplaceable() {
		t.Fatalf("after first write, only writer must be replaceable")
	}
	if _, err := sc.Read(make([]byte, 4)); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !sc.ReaderReplaceable() || !sc.WriterReplaceable() {
		t.Fatalf("after first read and write, both directions must be replaceable")
	}
}

func TestSmartHedgedDialWinsWithSecondCandidate(t *testing.T) {
	origDelay := smartHedgeDelayFn
	smartHedgeDelayFn = func(float64) time.Duration { return 30 * time.Millisecond }
	defer func() { smartHedgeDelayFn = origDelay }()

	slow := &hangingProxy{fakeProxy: newFakeProxy("Slow", 50), wait: 500 * time.Millisecond}
	fast := newFakeProxy("Fast", 200)
	fast.dialConn = &fakeConn{}
	s := newTestSmartWithProxies(slow, fast)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := s.DialContext(ctx, &C.Metadata{Host: "hedge.example.com"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("hedged dial failed: %v", err)
	}
	_ = conn.Close()

	if elapsed > 250*time.Millisecond {
		t.Fatalf("hedged second candidate should have won quickly, took %v", elapsed)
	}
	if fast.dialCalls != 1 {
		t.Fatalf("expected hedged second candidate to be dialed once, got %d", fast.dialCalls)
	}
}

func TestSmartServiceGroupPinDoesNotHedge(t *testing.T) {
	origDelay := smartHedgeDelayFn
	smartHedgeDelayFn = func(float64) time.Duration { return 10 * time.Millisecond }
	defer func() { smartHedgeDelayFn = origDelay }()

	primary := &hangingProxy{fakeProxy: newFakeProxy("Primary", 50), wait: 60 * time.Millisecond}
	secondary := newFakeProxy("Secondary", 200)
	s := newTestSmartWithProxies(primary, secondary)
	s.service = "openai"
	s.lastProbe = time.Now()

	conn, err := s.DialContext(context.Background(), &C.Metadata{Host: "chatgpt.com"})
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.Close()
	if secondary.dialCalls != 0 {
		t.Fatalf("service group pin must not hedge to a second IP, got %d calls", secondary.dialCalls)
	}
}

func TestScanServiceBodyStreamingWindow(t *testing.T) {
	preset := servicePresets["google-gemini"]
	// Place region marker across a 32KB chunk boundary.
	padding := strings.Repeat("a", serviceBodyChunk-5)
	body := padding + `,2,1,200,"USA"` + strings.Repeat("b", 1024*1024)
	region, unavail, err := scanServiceBody(preset, strings.NewReader(body))
	if err != nil {
		t.Fatalf("scanServiceBody error: %v", err)
	}
	if unavail || region != "USA" {
		t.Fatalf("expected USA available, got region=%q unavail=%t", region, unavail)
	}

	// Unavailable phrase across a chunk boundary must be caught.
	unavailBody := strings.Repeat("x", serviceBodyChunk-8) + "Not Supported In Your Country" + strings.Repeat("y", 1024)
	_, unavail, err = scanServiceBody(preset, strings.NewReader(unavailBody))
	if err != nil {
		t.Fatalf("scanServiceBody error: %v", err)
	}
	if !unavail {
		t.Fatalf("expected unavailable phrase across chunk boundary to match")
	}
}

func TestSmartImportStateFromAndSnapshot(t *testing.T) {
	now := time.Now()
	p1 := newFakeProxy("US-1", 120)
	p2 := newFakeProxy("HK-1", 40)
	oldGroup := newTestSmartWithProxies(p1, p2)
	oldGroup.service = "openai"
	oldGroup.states["US-1"] = &smartPolicyState{score: 95, lastSample: now}
	oldGroup.verdicts["US-1"] = serviceVerdict{at: now, known: true, blocked: false, region: "US"}
	oldGroup.verdicts["HK-1"] = serviceVerdict{at: now, known: true, blocked: true, region: "HK"}
	oldGroup.verdicts["Removed"] = serviceVerdict{at: now, known: true, region: "JP"}

	newGroup := newTestSmartWithProxies(p1, p2)
	newGroup.service = "openai"
	newGroup.ImportStateFrom(oldGroup)

	snap := newGroup.Snapshot()
	if snap.Service != "openai" || snap.Pin != "group" {
		t.Fatalf("unexpected snapshot meta: %+v", snap)
	}
	if m := snap.Members["US-1"]; !m.Verified || m.Blocked || m.Region != "US" || m.Score != 95 {
		t.Fatalf("US-1 state not imported accurately: %+v", m)
	}
	if m := snap.Members["HK-1"]; m.Verified || !m.Blocked || m.Region != "HK" {
		t.Fatalf("HK-1 state not imported accurately: %+v", m)
	}
	if _, ok := snap.Members["Removed"]; ok {
		t.Fatalf("removed member must not be imported")
	}

	// Verify MarshalJSON includes smart snapshot.
	raw, err := newGroup.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if _, ok := decoded["smart"]; !ok {
		t.Fatalf("MarshalJSON must include smart snapshot")
	}
}

func TestSmartCloseCancelsInFlightProbe(t *testing.T) {
	origProbe := probeServiceFunc
	canceled := make(chan struct{}, 1)
	var called atomic.Int32
	probeServiceFunc = func(ctx context.Context, proxy C.Proxy, service string, forced bool) (serviceVerdict, error) {
		called.Add(1)
		<-ctx.Done()
		select {
		case canceled <- struct{}{}:
		default:
		}
		return serviceVerdict{}, ctx.Err()
	}
	defer func() { probeServiceFunc = origProbe }()

	p := newFakeProxy("US-1", 100)
	s, err := NewSmart(GroupCommonOption{Name: "AI", URL: C.DefaultTestURL}, SmartOption{Service: "openai"}, p, []P.ProxyProvider{&fakeProvider{proxies: []C.Proxy{p}}})
	if err != nil {
		t.Fatalf("NewSmart failed: %v", err)
	}
	s.maybeProbeService(s.Proxies())
	time.Sleep(20 * time.Millisecond)
	_ = s.Close()

	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatalf("Close() must cancel in-flight service probes (called=%d)", called.Load())
	}
}

func TestSmartParserRespectsExplicitInterval(t *testing.T) {
	p := newFakeProxy("A", 100)
	proxyMap := map[string]C.Proxy{"A": p, "COMPATIBLE": p}
	providersMap := map[string]P.ProxyProvider{}

	group, err := ParseProxyGroup(map[string]any{
		"name":     "CustomSmart",
		"type":     "smart",
		"proxies":  []string{"A"},
		"interval": 120,
	}, proxyMap, providersMap, []string{"A"}, nil)
	if err != nil {
		t.Fatalf("ParseProxyGroup failed: %v", err)
	}
	smart := group.(*Smart)
	if smart.interval != 120*time.Second {
		t.Fatalf("expected explicit interval 120s, got %v", smart.interval)
	}
	_ = smart.Close()
}

// Keep io imported if needed by future stream tests.
var _ io.Reader = (*strings.Reader)(nil)

func BenchmarkSmartConnWriteHotPath(b *testing.B) {
	s := newTestSmart()
	conn := &fakeConn{}
	sc := newSmartConn(conn, s, "A", &C.Metadata{Host: "bench.example.com"}, time.Now(), 0)
	payload := make([]byte, 1024)
	// Warm up first write so we benchmark the steady-state hot path.
	_, _ = sc.Write(payload)
	conn.written = conn.written[:0]

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.written = conn.written[:0]
		_, _ = sc.Write(payload)
	}
}

func BenchmarkSmartSelectDialCandidates200(b *testing.B) {
	proxies := make([]C.Proxy, 200)
	for i := range proxies {
		proxies[i] = newFakeProxy(fmt.Sprintf("Node-%03d", i), uint16(50+i))
	}
	s := newTestSmartWithProxies(proxies...)
	s.priority, _ = parsePolicyPriority("Node-00:0.9;Node-1:1.2")
	meta := &C.Metadata{Host: "bench.example.com"}
	s.reportLatency("Node-000", meta, 55)
	s.rankedCandidates(proxies, time.Now())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = s.selectDialCandidates(meta, false, false)
	}
}

func BenchmarkSmartOrderedCandidates200(b *testing.B) {
	proxies := make([]C.Proxy, 200)
	for i := range proxies {
		proxies[i] = newFakeProxy(fmt.Sprintf("Node-%03d", i), uint16(50+i))
	}
	s := newTestSmartWithProxies(proxies...)
	s.priority, _ = parsePolicyPriority("Node-00:0.9;Node-1:1.2")
	meta := &C.Metadata{Host: "bench.example.com"}
	s.reportLatency("Node-000", meta, 55)
	s.rankedCandidates(proxies, time.Now())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.orderedCandidates(meta, false)
	}
}

func BenchmarkScanServiceBodyGemini(b *testing.B) {
	preset := servicePresets["google-gemini"]
	// Typical ~1MB Gemini HTML page with region payload at ~84%.
	page := strings.Repeat("x", 850*1024) + `,2,1,200,"USA"` + strings.Repeat("y", 150*1024)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		region, unavail, err := scanServiceBody(preset, strings.NewReader(page))
		if err != nil || unavail || region != "USA" {
			b.Fatalf("unexpected result: region=%q unavail=%t err=%v", region, unavail, err)
		}
	}
}

func BenchmarkReadServiceBodyLegacyGemini(b *testing.B) {
	preset := servicePresets["google-gemini"]
	page := strings.Repeat("x", 850*1024) + `,2,1,200,"USA"` + strings.Repeat("y", 150*1024)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body, err := readServiceBody(preset, strings.NewReader(page))
		if err != nil {
			b.Fatal(err)
		}
		v := evaluateServiceResponse(preset, 200, preset.url, body)
		if !v.known || v.blocked || v.region != "USA" {
			b.Fatalf("unexpected verdict: %+v", v)
		}
	}
}
