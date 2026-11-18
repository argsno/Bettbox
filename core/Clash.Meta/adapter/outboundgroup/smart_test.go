package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// fakeProxy implements C.Proxy with just enough behavior for scoring tests.
type fakeProxy struct {
	name       string
	delay      uint16
	alive      bool
	supportUDP bool
	l3         bool
	dialErr    error
	dialConn   C.Conn
	listenErr  error

	dialCalls   int
	listenCalls int
}

func newFakeProxy(name string, delay uint16) *fakeProxy {
	return &fakeProxy{name: name, delay: delay, alive: true}
}

func (f *fakeProxy) Name() string                    { return f.name }
func (f *fakeProxy) Type() C.AdapterType             { return C.Selector }
func (f *fakeProxy) Addr() string                    { return "" }
func (f *fakeProxy) SupportUDP() bool                { return f.supportUDP }
func (f *fakeProxy) SupportUOT() bool                { return false }
func (f *fakeProxy) ProxyInfo() C.ProxyInfo          { return C.ProxyInfo{} }
func (f *fakeProxy) MarshalJSON() ([]byte, error)    { return []byte("{}"), nil }
func (f *fakeProxy) Close() error                    { return nil }
func (f *fakeProxy) Adapter() C.ProxyAdapter         { return f }
func (f *fakeProxy) AliveForTestUrl(url string) bool { return f.alive }
func (f *fakeProxy) DelayHistory() []C.DelayHistory  { return nil }
func (f *fakeProxy) ExtraDelayHistories() map[string]C.ProxyState {
	return nil
}
func (f *fakeProxy) LastDelayForTestUrl(url string) uint16 { return f.delay }
func (f *fakeProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	return f.delay, nil
}
func (f *fakeProxy) IsL3Protocol(metadata *C.Metadata) bool { return f.l3 }
func (f *fakeProxy) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return f
}
func (f *fakeProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	f.dialCalls++
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	if f.dialConn != nil {
		return f.dialConn, nil
	}
	return nil, errors.New("not implemented")
}
func (f *fakeProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	f.listenCalls++
	if f.listenErr != nil {
		return nil, f.listenErr
	}
	return &fakePacketConn{}, nil
}

// fakePacketConn implements C.PacketConn so packet retry tests can observe the
// success path without a real socket.
type fakePacketConn struct {
	chains []C.ProxyAdapter
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error)     { return 0, nil, io.EOF }
func (f *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) { return len(b), nil }
func (f *fakePacketConn) Close() error                                 { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                          { return nil }
func (f *fakePacketConn) SetDeadline(t time.Time) error                { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error            { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error           { return nil }
func (f *fakePacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return nil, nil, nil, io.EOF
}
func (f *fakePacketConn) Chains() C.Chain                               { return nil }
func (f *fakePacketConn) ProviderChains() C.Chain                       { return nil }
func (f *fakePacketConn) AppendToChains(adapter C.ProxyAdapter)         { f.chains = append(f.chains, adapter) }
func (f *fakePacketConn) RemoteDestination() string                     { return "" }
func (f *fakePacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

var _ C.PacketConn = (*fakePacketConn)(nil)

func newTestSmart() *Smart {
	return &Smart{
		states:   make(map[string]*smartPolicyState),
		sites:    make(map[string]*smartSiteRecord),
		verdicts: make(map[string]serviceVerdict),
		attempts: make(map[string]time.Time),
	}
}

// fakeProvider serves a fixed proxy list so tests can exercise candidate
// ordering and group dialing without a real provider.
type fakeProvider struct {
	proxies []C.Proxy
}

func (f *fakeProvider) Name() string               { return "fake" }
func (f *fakeProvider) VehicleType() P.VehicleType { return P.Inline }
func (f *fakeProvider) Type() P.ProviderType       { return P.Proxy }
func (f *fakeProvider) Initial() error             { return nil }
func (f *fakeProvider) Update() error              { return nil }
func (f *fakeProvider) Proxies() []C.Proxy         { return f.proxies }
func (f *fakeProvider) Count() int                 { return len(f.proxies) }
func (f *fakeProvider) Touch()                     {}
func (f *fakeProvider) HealthCheck()               {}
func (f *fakeProvider) Version() uint32            { return 1 }
func (f *fakeProvider) HealthCheckURL() string     { return "" }
func (f *fakeProvider) RegisterHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
}

func newTestSmartWithProxies(proxies ...C.Proxy) *Smart {
	s := newTestSmart()
	s.GroupBase = NewGroupBase(GroupBaseOption{
		Name:        "smart",
		Type:        C.Smart,
		TestTimeout: 1000,
		Providers:   []P.ProxyProvider{&fakeProvider{proxies: proxies}},
	})
	s.testUrl = C.DefaultTestURL
	return s
}

// fakeConn implements C.Conn for smartConn tests: reads drain readData, writes
// are captured, and Close only counts calls.
type fakeConn struct {
	mu       sync.Mutex
	readData []byte
	written  []byte
	closes   int
}

func (f *fakeConn) Read(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(b, f.readData)
	f.readData = f.readData[n:]
	return n, nil
}

func (f *fakeConn) ReadBuffer(buffer *buf.Buffer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.readData) == 0 {
		return io.EOF
	}
	_, err := buffer.Write(f.readData)
	f.readData = nil
	return err
}

func (f *fakeConn) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, b...)
	return len(b), nil
}

func (f *fakeConn) WriteBuffer(buffer *buf.Buffer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, buffer.Bytes()...)
	return nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}
func (f *fakeConn) LocalAddr() net.Addr                   { return nil }
func (f *fakeConn) RemoteAddr() net.Addr                  { return nil }
func (f *fakeConn) SetDeadline(time.Time) error           { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error       { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error      { return nil }
func (f *fakeConn) Chains() C.Chain                       { return nil }
func (f *fakeConn) ProviderChains() C.Chain               { return nil }
func (f *fakeConn) AppendToChains(adapter C.ProxyAdapter) {}
func (f *fakeConn) RemoteDestination() string             { return "" }

func TestSmartObserveLatency(t *testing.T) {
	now := time.Now()

	st := &smartPolicyState{}
	st.observeLatency(100, now)
	if st.score != 100 {
		t.Fatalf("first sample must seed the score, got %v", st.score)
	}

	st.observeLatency(200, now)
	want := 100*(1-smartEwmaAlpha) + 200*smartEwmaAlpha
	if math.Abs(st.score-want) > 0.001 {
		t.Fatalf("ewma mismatch, got %v want %v", st.score, want)
	}

	low := &smartPolicyState{}
	low.observeLatency(0.1, now)
	if low.score != smartMinScore {
		t.Fatalf("score must clamp to the minimum, got %v", low.score)
	}

	high := &smartPolicyState{}
	high.observeLatency(1e9, now)
	if high.score != smartMaxScore {
		t.Fatalf("score must clamp to the maximum, got %v", high.score)
	}
}

func TestSmartFailurePenalty(t *testing.T) {
	now := time.Now()
	st := &smartPolicyState{}
	st.observeLatency(100, now)
	base := st.effectiveScore(smartUnknownScore, now)

	st.observeFailure(now)
	if got := st.effectiveScore(smartUnknownScore, now); got <= base {
		t.Fatalf("failure must worsen the effective score, got %v base %v", got, base)
	}

	later := now.Add(smartFailCooldown + time.Second)
	// The penalty must expire, leaving only the normal aging of the latency
	// sample toward the fallback.
	reference := &smartPolicyState{}
	reference.observeLatency(100, now)
	wantExpired := reference.effectiveScore(smartUnknownScore, later)
	if got := st.effectiveScore(smartUnknownScore, later); math.Abs(got-wantExpired) > 0.001 {
		t.Fatalf("failure penalty must expire with the cooldown, got %v want %v", got, wantExpired)
	}

	st.observeLatency(100, later)
	if st.failStreak != 0 {
		t.Fatalf("success must reset the failure streak, got %d", st.failStreak)
	}
}

func TestSmartLossPenalty(t *testing.T) {
	now := time.Now()
	st := &smartPolicyState{}
	st.observeLoss(0.01, now)
	if math.Abs(st.lossPenalty-50) > 0.001 {
		t.Fatalf("1%% loss must add 50ms, got %v", st.lossPenalty)
	}

	st.observeLoss(0.10, now)
	if math.Abs(st.lossPenalty-275) > 0.001 {
		t.Fatalf("loss penalty must smooth toward the new value, got %v", st.lossPenalty)
	}

	capped := &smartPolicyState{}
	capped.observeLoss(1.0, now)
	if capped.lossPenalty != smartLossPenaltyMax {
		t.Fatalf("loss penalty must be capped, got %v", capped.lossPenalty)
	}
}

func TestSmartUsageDecay(t *testing.T) {
	now := time.Now()
	st := &smartPolicyState{}
	st.bumpUsage(now)
	st.bumpUsage(now)
	if got := st.decayedUsage(now); got != 2 {
		t.Fatalf("usage mismatch, got %v", got)
	}

	after := now.Add(smartUsageHalfLife)
	if got := st.decayedUsage(after); math.Abs(got-1) > 0.001 {
		t.Fatalf("usage must halve per half-life, got %v", got)
	}
}

func TestSmartScoreAging(t *testing.T) {
	now := time.Now()
	st := &smartPolicyState{}
	st.observeLatency(1000, now)
	if !st.lastSample.Equal(now) {
		t.Fatalf("a latency sample must record its timestamp, got %v", st.lastSample)
	}

	fallback := 100.0
	if got := st.effectiveScore(fallback, now); math.Abs(got-1000) > 0.001 {
		t.Fatalf("a fresh sample must be used as-is, got %v", got)
	}

	// After one half-life the sample is halfway between itself and the fallback.
	half := now.Add(smartScoreHalfLife)
	want := fallback + (1000-fallback)*0.5
	if got := st.effectiveScore(fallback, half); math.Abs(got-want) > 0.001 {
		t.Fatalf("a stale sample must relax toward the fallback, got %v want %v", got, want)
	}

	// Two half-lives leave a quarter of the original distance.
	want = fallback + (1000-fallback)*0.25
	if got := st.effectiveScore(fallback, now.Add(2*smartScoreHalfLife)); math.Abs(got-want) > 0.001 {
		t.Fatalf("aging must follow the half-life curve, got %v want %v", got, want)
	}

	// No sample, or no sample timestamp, falls back to the URL-test delay.
	if got := (&smartPolicyState{}).effectiveScore(250, now); got != 250 {
		t.Fatalf("an unknown score must use the fallback, got %v", got)
	}
	if got := (&smartPolicyState{score: 1000}).effectiveScore(250, now); got != 250 {
		t.Fatalf("a sample without a timestamp must use the fallback, got %v", got)
	}

	// The aged score is clamped to the configured range.
	if got := (&smartPolicyState{score: 100000, lastSample: now}).effectiveScore(50000, now); got != smartMaxScore {
		t.Fatalf("the aged score must clamp to the maximum, got %v", got)
	}
	if got := (&smartPolicyState{score: 0.5, lastSample: now}).effectiveScore(0, now); got != smartMinScore {
		t.Fatalf("the aged score must clamp to the minimum, got %v", got)
	}
}

func TestSmartLossDecay(t *testing.T) {
	now := time.Now()
	st := &smartPolicyState{}
	st.observeLoss(0.01, now) // 50ms
	if !st.lossUpdated.Equal(now) {
		t.Fatalf("a loss sample must record its timestamp, got %v", st.lossUpdated)
	}
	if got := st.decayedLoss(now); math.Abs(got-50) > 0.001 {
		t.Fatalf("a fresh loss penalty must be used as-is, got %v", got)
	}
	if got := st.decayedLoss(now.Add(smartLossHalfLife)); math.Abs(got-25) > 0.001 {
		t.Fatalf("the loss penalty must halve per half-life, got %v", got)
	}

	// Without a timestamp the stored penalty is kept unchanged.
	untimed := &smartPolicyState{lossPenalty: 80}
	if got := untimed.decayedLoss(now.Add(time.Hour)); got != 80 {
		t.Fatalf("a penalty without a timestamp must stay unchanged, got %v", got)
	}

	// effectiveScore reflects the decayed penalty.
	latency := &smartPolicyState{score: 100, lastSample: now, lossPenalty: 100, lossUpdated: now}
	if got := latency.effectiveScore(100, now); math.Abs(got-200) > 0.001 {
		t.Fatalf("a fresh loss penalty must be added in full, got %v", got)
	}
	if got := latency.effectiveScore(100, now.Add(smartLossHalfLife)); math.Abs(got-150) > 0.001 {
		t.Fatalf("a stale loss penalty must be halved after one half-life, got %v", got)
	}
}

func TestSmartFailureCooldownGrowth(t *testing.T) {
	now := time.Now()
	st := &smartPolicyState{}
	st.observeFailure(now)
	if st.failStreak != 1 || st.failCooldown() != smartFailCooldown {
		t.Fatalf("the first failure must start a one-minute cooldown, got streak %d cooldown %v", st.failStreak, st.failCooldown())
	}

	second := now.Add(30 * time.Second) // still inside the first cooldown
	st.observeFailure(second)
	if st.failStreak != 2 {
		t.Fatalf("a failure inside the cooldown must extend the streak, got %d", st.failStreak)
	}
	if st.failCooldown() != 2*smartFailCooldown {
		t.Fatalf("the cooldown must double per streak, got %v", st.failCooldown())
	}

	// The grown cooldown keeps the penalty alive past the old one-minute window.
	if got := st.effectiveScore(smartUnknownScore, second.Add(30*time.Second)); got <= smartUnknownScore {
		t.Fatalf("the failure penalty must survive the grown cooldown, got %v", got)
	}
	expired := second.Add(2*smartFailCooldown + time.Second)
	if got := st.effectiveScore(smartUnknownScore, expired); got != smartUnknownScore {
		t.Fatalf("the failure penalty must expire after the grown cooldown, got %v", got)
	}

	// The cooldown is capped at smartFailCooldownMax.
	capped := &smartPolicyState{}
	for i := 0; i < 6; i++ {
		capped.observeFailure(now.Add(time.Duration(i) * time.Second))
	}
	if capped.failStreak != 6 {
		t.Fatalf("fast failures must keep extending the streak, got %d", capped.failStreak)
	}
	if capped.failCooldown() != smartFailCooldownMax {
		t.Fatalf("the cooldown must cap at the maximum, got %v", capped.failCooldown())
	}

	// A failure after the current cooldown elapsed starts a new streak.
	reset := &smartPolicyState{}
	reset.observeFailure(now)
	reset.observeFailure(now.Add(30 * time.Second))
	if reset.failCooldown() != 2*smartFailCooldown {
		t.Fatalf("test setup: expected a two-minute cooldown, got %v", reset.failCooldown())
	}
	reset.observeFailure(now.Add(30*time.Second + 2*smartFailCooldown + time.Second))
	if reset.failStreak != 1 {
		t.Fatalf("a failure after the cooldown must reset the streak, got %d", reset.failStreak)
	}
}

func TestParsePolicyPriority(t *testing.T) {
	rules, err := parsePolicyPriority("Premium:0.9;Backup:1.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := &Smart{priority: rules}
	if got := s.priorityFactor("Premium-US-01"); got != 0.9 {
		t.Fatalf("premium factor mismatch, got %v", got)
	}
	if got := s.priorityFactor("Backup-1"); got != 1.3 {
		t.Fatalf("backup factor mismatch, got %v", got)
	}
	if got := s.priorityFactor("Other"); got != 1.0 {
		t.Fatalf("default factor mismatch, got %v", got)
	}

	firstWins, err := parsePolicyPriority("^A:0.5;.*:2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s = &Smart{priority: firstWins}
	if got := s.priorityFactor("AB"); got != 0.5 {
		t.Fatalf("first matching rule must win, got %v", got)
	}
	if got := s.priorityFactor("B"); got != 2 {
		t.Fatalf("catch-all rule mismatch, got %v", got)
	}

	for _, invalid := range []string{"Broken", "A:0", "A:-1", "A:abc", "A:1e999"} {
		if _, err := parsePolicyPriority(invalid); err == nil {
			t.Fatalf("expected error for %q", invalid)
		}
	}

	if rules, err := parsePolicyPriority(""); err != nil || len(rules) != 0 {
		t.Fatalf("empty value must yield no rules, got %v err %v", rules, err)
	}
}

func TestSmartPolicyPriorityPenaltiesKeepFullWeight(t *testing.T) {
	now := time.Now()
	premium := newFakeProxy("Premium-US", 400)
	s := newTestSmartWithProxies(premium)
	rules, err := parsePolicyPriority("Premium:0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.priority = rules

	st := &smartPolicyState{}
	st.observeLatency(400, now)
	if got := s.scoreOf(premium, st, now); math.Abs(got-200) > 0.001 {
		t.Fatalf("the factor must scale the latency, got %v want 200", got)
	}

	// A premium factor must not discount observed damage: the failure penalty
	// is added after the factor, so it stays at 600ms rather than 300ms.
	st.observeFailure(now)
	if got, want := s.scoreOf(premium, st, now), 200+smartFailPenalty; math.Abs(got-want) > 0.001 {
		t.Fatalf("the failure penalty must keep its full weight, got %v want %v", got, want)
	}

	// Same for the loss penalty: 1% retransmission stays 50ms, not 25ms.
	st = &smartPolicyState{}
	st.observeLatency(400, now)
	st.observeLoss(0.01, now)
	if got, want := s.scoreOf(premium, st, now), 200+smartLossPenaltyPerPct; math.Abs(got-want) > 0.001 {
		t.Fatalf("the loss penalty must keep its full weight, got %v want %v", got, want)
	}

	// The unscaled helper still carries the penalty, so the documented
	// effectiveScore semantics are unchanged.
	if got, want := st.effectiveScore(400, now), 400+smartLossPenaltyPerPct; math.Abs(got-want) > 0.001 {
		t.Fatalf("effectiveScore must keep the penalty at factor 1, got %v want %v", got, want)
	}
}

func TestSmartSiteMemory(t *testing.T) {
	s := newTestSmart()
	now := time.Now()
	metadata := &C.Metadata{Host: "www.example.com"}

	s.rememberSite(metadata, "A", true, now)
	s.rememberSite(metadata, "B", false, now)

	key := getKey(metadata)
	record, ok := s.sites[key]
	if !ok {
		t.Fatalf("site memory must be recorded under %q", key)
	}
	if record.proxies["A"].lastSuccess.IsZero() {
		t.Fatalf("success must be remembered")
	}
	if record.proxies["B"].lastFailure.IsZero() {
		t.Fatalf("failure must be remembered")
	}

	// success after failure wins the freshness comparison used by selection
	s.rememberSite(metadata, "B", true, now.Add(time.Second))
	entry := record.proxies["B"]
	if !entry.lastSuccess.After(entry.lastFailure) {
		t.Fatalf("later success must override earlier failure")
	}

	record.updated = now.Add(-2 * smartSiteMemoryTTL)
	s.pruneSites(now)
	if len(s.sites) != 0 {
		t.Fatalf("expired site records must be pruned, got %d", len(s.sites))
	}
}

func TestSmartSiteFailureTTL(t *testing.T) {
	now := time.Now()

	t.Run("fresh failure suspends the faster policy", func(t *testing.T) {
		fast := newFakeProxy("Fast", 100)
		slow := newFakeProxy("Slow", 400)
		s := newTestSmartWithProxies(fast, slow)
		metadata := &C.Metadata{Host: "fresh.example.com"}
		s.rememberSite(metadata, "Fast", false, now)

		order := s.orderedCandidates(metadata, false)
		if len(order) != 2 || order[0].Name() != "Slow" {
			t.Fatalf("a fresh site failure must push the faster policy back, got %v", order)
		}
	})

	t.Run("expired failure no longer suspends it", func(t *testing.T) {
		fast := newFakeProxy("Fast", 100)
		slow := newFakeProxy("Slow", 400)
		s := newTestSmartWithProxies(fast, slow)
		metadata := &C.Metadata{Host: "expired.example.com"}
		s.rememberSite(metadata, "Fast", false, now.Add(-smartSiteFailureTTL-time.Second))

		for i := 0; i < 16; i++ {
			order := s.orderedCandidates(metadata, false)
			if order[0].Name() != "Fast" {
				t.Fatalf("a failure older than the failure TTL must not suspend the policy, got %v on call %d", order[0].Name(), i)
			}
		}
	})

	t.Run("prune drops stale failures but keeps fresh successes", func(t *testing.T) {
		s := newTestSmart()
		metadata := &C.Metadata{Host: "prune.example.com"}
		s.rememberSite(metadata, "Fail", false, now.Add(-smartSiteFailureTTL-time.Second))
		s.rememberSite(metadata, "OK", true, now.Add(-smartSiteMemoryTTL+time.Second))
		s.pruneSites(now)

		record := s.sites[getKey(metadata)]
		if record == nil {
			t.Fatalf("a record with a fresh success must survive pruning")
		}
		if _, ok := record.proxies["Fail"]; ok {
			t.Fatalf("an expired failure must be pruned")
		}
		if _, ok := record.proxies["OK"]; !ok {
			t.Fatalf("a fresh success must be kept")
		}
	})

	t.Run("empty records are dropped", func(t *testing.T) {
		s := newTestSmart()
		metadata := &C.Metadata{Host: "empty.example.com"}
		s.rememberSite(metadata, "A", false, now.Add(-smartSiteFailureTTL-time.Second))
		s.pruneSites(now)
		if len(s.sites) != 0 {
			t.Fatalf("a record whose entries all expired must be dropped, got %d", len(s.sites))
		}
	})
}

func TestSmartSiteMemoryEvictsOldestRecord(t *testing.T) {
	s := newTestSmart()
	base := time.Now()

	// Use IP hosts so every host maps to its own key rather than a shared eTLD+1.
	for i := 0; i < smartSiteMemoryMaxSites; i++ {
		host := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		metadata := &C.Metadata{Host: host}
		s.rememberSite(metadata, "A", true, base.Add(time.Duration(i)*time.Second))
	}
	if len(s.sites) != smartSiteMemoryMaxSites {
		t.Fatalf("test setup: expected a full site table, got %d", len(s.sites))
	}

	oldest := &C.Metadata{Host: "10.0.0.0"}
	newSite := &C.Metadata{Host: "192.0.2.200"}
	s.rememberSite(newSite, "A", true, base.Add(time.Duration(smartSiteMemoryMaxSites)*time.Second))

	if len(s.sites) != smartSiteMemoryMaxSites {
		t.Fatalf("a full table must stay at the cap after eviction, got %d", len(s.sites))
	}
	if _, ok := s.sites[getKey(newSite)]; !ok {
		t.Fatalf("the new site must be remembered")
	}
	if _, ok := s.sites[getKey(oldest)]; ok {
		t.Fatalf("the least-recently-updated site must be evicted")
	}
}

func TestSmartScoreOfUsesURLTestFallback(t *testing.T) {
	s := newTestSmart()
	now := time.Now()
	proxy := newFakeProxy("A", 120)

	// no real-connection sample yet: the URL test delay seeds the score
	if got := s.scoreOf(proxy, nil, now); got != 120 {
		t.Fatalf("url test delay must seed the score, got %v", got)
	}

	st := &smartPolicyState{}
	st.observeLatency(300, now)
	if got := s.scoreOf(proxy, st, now); got != 300 {
		t.Fatalf("real samples must take precedence, got %v", got)
	}

	st.observeFailure(now)
	if got := s.scoreOf(proxy, st, now); got <= 300 {
		t.Fatalf("failure must be reflected, got %v", got)
	}
}

func TestSmartConnCloseFailureSemantics(t *testing.T) {
	metadata := &C.Metadata{Host: "close.example.com"}

	t.Run("close before write", func(t *testing.T) {
		s := newTestSmart()
		conn := &fakeConn{}
		sc := newSmartConn(conn, s, "A", metadata, time.Now(), 0).(*smartConn)

		if err := sc.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
		if conn.closes != 1 {
			t.Fatalf("the wrapped connection must be closed once, got %d", conn.closes)
		}
		if st := s.states["A"]; st != nil {
			t.Fatalf("a connection closed before any write must not create node state, got %+v", st)
		}
		if record := s.sites[getKey(metadata)]; record != nil {
			t.Fatalf("a connection closed before any write must not record site state, got %+v", record)
		}
	})

	t.Run("write then close before read", func(t *testing.T) {
		s := newTestSmart()
		conn := &fakeConn{}
		sc := newSmartConn(conn, s, "A", metadata, time.Now(), 0).(*smartConn)

		if _, err := sc.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := sc.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
		st := s.states["A"]
		if st == nil || st.failStreak != 1 {
			t.Fatalf("an unanswered request must fail the node, got %+v", st)
		}
		record := s.sites[getKey(metadata)]
		if record == nil || record.proxies["A"] == nil || record.proxies["A"].lastFailure.IsZero() {
			t.Fatalf("an unanswered request must record a site failure")
		}
	})

	t.Run("write then read then close", func(t *testing.T) {
		s := newTestSmart()
		conn := &fakeConn{readData: []byte("HTTP/1.1 200 OK\r\n\r\n")}
		sc := newSmartConn(conn, s, "A", metadata, time.Now(), 0).(*smartConn)

		if _, err := sc.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if _, err := sc.Read(make([]byte, 4)); err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if err := sc.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
		if st := s.states["A"]; st == nil || st.failStreak != 0 {
			t.Fatalf("an answered request must not fail the node, got %+v", st)
		}
	})
}

func TestSmartConnConcurrentWriteReadClose(t *testing.T) {
	s := newTestSmart()
	metadata := &C.Metadata{Host: "concurrent.example.com"}
	conn := &fakeConn{readData: []byte("ok")}
	sc := newSmartConn(conn, s, "A", metadata, time.Now(), 0)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		_, _ = sc.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}()
	go func() {
		defer wg.Done()
		_, _ = sc.Read(make([]byte, 2))
	}()
	go func() {
		defer wg.Done()
		_ = sc.Close()
	}()
	wg.Wait()
}

func TestSmartConnFirstByteLatencyBase(t *testing.T) {
	t.Run("no write starts at dial completion", func(t *testing.T) {
		s := newTestSmart()
		metadata := &C.Metadata{Host: "server-first.example.com"}
		conn := &fakeConn{readData: []byte("ok")}
		sc := newSmartConn(conn, s, "A", metadata, time.Now().Add(-250*time.Millisecond), 0).(*smartConn)

		if _, err := sc.Read(make([]byte, 2)); err != nil {
			t.Fatalf("read failed: %v", err)
		}
		got := s.states["A"].score
		if got < 250 {
			t.Fatalf("without a write the sample must start at dial completion, got %vms", got)
		}
		if got > 5000 {
			t.Fatalf("latency sample is implausibly large: %vms", got)
		}
	})

	t.Run("first write after dial completion", func(t *testing.T) {
		s := newTestSmart()
		metadata := &C.Metadata{Host: "request-first.example.com"}
		conn := &fakeConn{readData: []byte("ok")}
		sc := newSmartConn(conn, s, "A", metadata, time.Now().Add(-time.Hour), 0).(*smartConn)

		if _, err := sc.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if _, err := sc.Read(make([]byte, 2)); err != nil {
			t.Fatalf("read failed: %v", err)
		}
		got := s.states["A"].score
		if got < smartMinScore || got > 1000 {
			t.Fatalf("the sample must start at the first write, not the dial, got %vms", got)
		}
	})

	t.Run("first buffered write after dial completion", func(t *testing.T) {
		s := newTestSmart()
		metadata := &C.Metadata{Host: "buffered.example.com"}
		conn := &fakeConn{readData: []byte("ok")}
		sc := newSmartConn(conn, s, "A", metadata, time.Now().Add(-time.Hour), 0).(*smartConn)

		if err := sc.WriteBuffer(buf.As([]byte("GET / HTTP/1.1\r\n\r\n"))); err != nil {
			t.Fatalf("buffered write failed: %v", err)
		}
		if _, err := sc.Read(make([]byte, 2)); err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if got := s.states["A"].score; got < smartMinScore || got > 1000 {
			t.Fatalf("a buffered write must also start the latency clock, got %vms", got)
		}
	})

	t.Run("dial latency is added back", func(t *testing.T) {
		base := time.Unix(100, 0)
		got := firstResponseDelay(base, base.Add(50*time.Millisecond), 100*time.Millisecond)
		if got != 150*time.Millisecond {
			t.Fatalf("the dial leg must be added back to keep the URLTest basis, got %v", got)
		}
	})

	t.Run("smartConn includes the dial latency field", func(t *testing.T) {
		s := newTestSmart()
		metadata := &C.Metadata{Host: "dial-leg.example.com"}
		conn := &fakeConn{readData: []byte("ok")}
		sc := newSmartConn(conn, s, "A", metadata, time.Now().Add(-50*time.Millisecond), 100*time.Millisecond).(*smartConn)

		if _, err := sc.Read(make([]byte, 2)); err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if got := s.states["A"].score; got < 150 || got > 5000 {
			t.Fatalf("the sample must include the dial leg, got %vms", got)
		}
	})
}

func TestSmartReportLatencyLimitsAndRemembersSite(t *testing.T) {
	s := newTestSmart()
	metadata := &C.Metadata{Host: "slow.example.com"}

	s.reportLatency("Slow", metadata, 45_000)
	if _, ok := s.states["Slow"]; ok {
		t.Fatalf("an out-of-range sample must not create a latency score, got %+v", s.states["Slow"])
	}
	record := s.sites[getKey(metadata)]
	if record == nil || record.proxies["Slow"] == nil || record.proxies["Slow"].lastSuccess.IsZero() {
		t.Fatalf("a dropped latency sample must still record the site success")
	}

	s.reportLatency("Fast", metadata, 0.2)
	if got := s.states["Fast"].score; got != smartMinScore {
		t.Fatalf("an under-minimum sample must clamp to the minimum, got %v", got)
	}
	if record.proxies["Fast"] == nil || record.proxies["Fast"].lastSuccess.IsZero() {
		t.Fatalf("an under-minimum sample must still record the site success")
	}
}

func TestSmartHealthCheckResetsOnlyAliveProxies(t *testing.T) {
	alive := newFakeProxy("Alive", 100)
	dead := newFakeProxy("Dead", 100)
	dead.alive = false
	s := newTestSmartWithProxies(alive, dead)

	now := time.Now()
	s.mu.Lock()
	aliveState := s.stateOf("Alive")
	aliveState.observeFailure(now)
	deadState := s.stateOf("Dead")
	deadState.observeFailure(now)
	s.mu.Unlock()

	s.healthCheck()

	s.mu.Lock()
	defer s.mu.Unlock()
	if aliveState.failStreak != 0 {
		t.Fatalf("a successful health check must clear the alive policy's streak, got %d", aliveState.failStreak)
	}
	if deadState.failStreak != 1 {
		t.Fatalf("a dead policy must keep its streak, got %d", deadState.failStreak)
	}
}

func TestSmartDialContextFailureClassification(t *testing.T) {
	metadata := &C.Metadata{Host: "canceled.example.com"}

	t.Run("unsupported is not a node failure", func(t *testing.T) {
		proxy := newFakeProxy("A", 100)
		proxy.dialErr = C.ErrNotSupport
		s := newTestSmartWithProxies(proxy)

		conn, err := s.DialContext(context.Background(), metadata)
		if conn != nil || !errors.Is(err, C.ErrNotSupport) {
			t.Fatalf("dial must return the unsupported error, got conn %v err %v", conn, err)
		}
		if _, ok := s.states["A"]; ok {
			t.Fatalf("ErrNotSupport must not create node state, got %+v", s.states["A"])
		}
		if _, ok := s.sites[getKey(metadata)]; ok {
			t.Fatalf("ErrNotSupport must not record site state")
		}
	})

	t.Run("caller canceled before dial", func(t *testing.T) {
		proxy := newFakeProxy("A", 100)
		s := newTestSmartWithProxies(proxy)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := s.DialContext(ctx, metadata); !errors.Is(err, context.Canceled) {
			t.Fatalf("dial must return the caller cancellation, got %v", err)
		}
		if proxy.dialCalls != 0 {
			t.Fatalf("a canceled caller must not dial, got %d calls", proxy.dialCalls)
		}
		if _, ok := s.states["A"]; ok {
			t.Fatalf("caller cancellation must not create node state, got %+v", s.states["A"])
		}
	})

	t.Run("caller deadline before dial", func(t *testing.T) {
		proxy := newFakeProxy("A", 100)
		s := newTestSmartWithProxies(proxy)
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()

		if _, err := s.DialContext(ctx, metadata); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dial must return the caller deadline, got %v", err)
		}
		if proxy.dialCalls != 0 {
			t.Fatalf("a caller deadline must not dial, got %d calls", proxy.dialCalls)
		}
		if _, ok := s.states["A"]; ok {
			t.Fatalf("caller deadline must not create node state, got %+v", s.states["A"])
		}
	})

	t.Run("node deadline is a failure", func(t *testing.T) {
		proxy := newFakeProxy("A", 100)
		proxy.dialErr = context.DeadlineExceeded
		s := newTestSmartWithProxies(proxy)

		if _, err := s.DialContext(context.Background(), metadata); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dial must return the node deadline, got %v", err)
		}
		st := s.states["A"]
		if st == nil || st.failStreak != 1 {
			t.Fatalf("a node deadline with a live caller context must fail the node, got %+v", st)
		}
		record := s.sites[getKey(metadata)]
		if record == nil || record.proxies["A"] == nil || record.proxies["A"].lastFailure.IsZero() {
			t.Fatalf("a node deadline must record a site failure")
		}
	})

	t.Run("node error", func(t *testing.T) {
		proxy := newFakeProxy("B", 100)
		proxy.dialErr = errors.New("connection reset by peer")
		s := newTestSmartWithProxies(proxy)

		if _, err := s.DialContext(context.Background(), metadata); err == nil {
			t.Fatalf("dial must fail")
		}
		st := s.states["B"]
		if st == nil || st.failStreak != 1 {
			t.Fatalf("a node error must still fail the node, got %+v", st)
		}
	})
}

func TestSmartPreferredGapFloorIsFiveMilliseconds(t *testing.T) {
	if smartPreferredGapMin != 5.0 {
		t.Fatalf("the preferred-set floor must be 5ms, got %v", smartPreferredGapMin)
	}
	if smartPreferredGapRatio != 0.15 || smartSitePreferredGap != 0.4 {
		t.Fatalf("the other gap constants must stay unchanged: ratio %v site %v", smartPreferredGapRatio, smartSitePreferredGap)
	}

	// 14ms is inside the 5ms floor below the 10ms best; 22ms is outside it but
	// inside the old 20ms floor. Only policies inside the gap may lead.
	best := newFakeProxy("Best", 10)
	near := newFakeProxy("Near", 14)
	far := newFakeProxy("Far", 22)
	s := newTestSmartWithProxies(best, near, far)
	metadata := &C.Metadata{Host: "gap.example.com"}

	seen := make(map[string]bool, 2)
	for i := 0; i < 200; i++ {
		order := s.orderedCandidates(metadata, false)
		if len(order) != 3 {
			t.Fatalf("expected every candidate, got %d", len(order))
		}
		first := order[0].Name()
		if first == "Far" {
			t.Fatalf("a policy outside the gap must never lead, got %v", first)
		}
		seen[first] = true
	}
	if !seen["Best"] || !seen["Near"] {
		t.Fatalf("every policy inside the gap must be eligible, saw %v", seen)
	}
}

// countingProxy counts the state reads the ranking path performs so a cache hit
// can be distinguished from a rebuild.
type countingProxy struct {
	*fakeProxy
	delayReads atomic.Int64
	aliveReads atomic.Int64
}

func newCountingProxy(name string, delay uint16) *countingProxy {
	return &countingProxy{fakeProxy: newFakeProxy(name, delay)}
}

func (p *countingProxy) LastDelayForTestUrl(url string) uint16 {
	p.delayReads.Add(1)
	return p.fakeProxy.LastDelayForTestUrl(url)
}

func (p *countingProxy) AliveForTestUrl(url string) bool {
	p.aliveReads.Add(1)
	return p.fakeProxy.AliveForTestUrl(url)
}

func TestSmartRankingCacheSharesStateReads(t *testing.T) {
	fast := newCountingProxy("Fast", 100)
	slow := newCountingProxy("Slow", 400)
	s := newTestSmartWithProxies(fast, slow)
	metadata := &C.Metadata{Host: "cache.example.com"}

	s.orderedCandidates(metadata, false)
	delayReads := fast.delayReads.Load() + slow.delayReads.Load()
	aliveReads := fast.aliveReads.Load() + slow.aliveReads.Load()
	if delayReads == 0 || aliveReads == 0 {
		t.Fatalf("the first call must build the ranking, got %d delay and %d alive reads", delayReads, aliveReads)
	}

	for i := 0; i < 8; i++ {
		s.orderedCandidates(metadata, false)
	}
	if got := fast.delayReads.Load() + slow.delayReads.Load(); got != delayReads {
		t.Fatalf("a cached ranking must not re-read delays: %d -> %d", delayReads, got)
	}
	if got := fast.aliveReads.Load() + slow.aliveReads.Load(); got != aliveReads {
		t.Fatalf("a cached ranking must not re-read alive state: %d -> %d", aliveReads, got)
	}

	s.reportFailure("Fast", metadata)
	s.orderedCandidates(metadata, false)
	if got := fast.delayReads.Load() + slow.delayReads.Load(); got == delayReads {
		t.Fatalf("a failure must invalidate the cached ranking")
	}
}

func TestSmartRankingCacheKeepsSiteMemoryFresh(t *testing.T) {
	fast := newFakeProxy("Fast", 100)
	slow := newFakeProxy("Slow", 400)
	s := newTestSmartWithProxies(fast, slow)
	metadata := &C.Metadata{Host: "stale-cache.example.com"}

	// Prime the ranking, then record a failure without invalidating it.
	s.orderedCandidates(metadata, false)
	s.rememberSite(metadata, "Fast", false, time.Now())

	order := s.orderedCandidates(metadata, false)
	if len(order) != 2 || order[0].Name() != "Slow" {
		t.Fatalf("site memory must still apply to a cached ranking, got %v", order)
	}
}

// versionedProvider lets a test change the member list the way a subscription
// update does: bump the version, then serve the new proxies.
type versionedProvider struct {
	fakeProvider
	version uint32
}

func (f *versionedProvider) Version() uint32 { return f.version }

func TestSmartRankingCacheFollowsMembership(t *testing.T) {
	first := newCountingProxy("First", 100)
	second := newCountingProxy("Second", 200)
	provider := &versionedProvider{
		fakeProvider: fakeProvider{proxies: []C.Proxy{first}},
		version:      1,
	}
	s := newTestSmart()
	s.GroupBase = NewGroupBase(GroupBaseOption{
		Name:        "smart",
		Type:        C.Smart,
		TestTimeout: 1000,
		Providers:   []P.ProxyProvider{provider},
	})
	s.testUrl = C.DefaultTestURL
	metadata := &C.Metadata{Host: "members.example.com"}

	if order := s.orderedCandidates(metadata, false); len(order) != 1 {
		t.Fatalf("expected the initial member, got %v", order)
	}

	provider.proxies = []C.Proxy{first, second}
	provider.version = 2

	order := s.orderedCandidates(metadata, false)
	if len(order) != 2 {
		t.Fatalf("a membership change must rebuild the ranking, got %v", order)
	}
	if second.aliveReads.Load() == 0 || second.delayReads.Load() == 0 {
		t.Fatalf("the new member must be scored")
	}
}

func TestSmartHealthCheckInvalidatesRanking(t *testing.T) {
	fast := newCountingProxy("Fast", 100)
	slow := newCountingProxy("Slow", 400)
	s := newTestSmartWithProxies(fast, slow)
	metadata := &C.Metadata{Host: "health.example.com"}

	s.orderedCandidates(metadata, false)
	delayReads := fast.delayReads.Load() + slow.delayReads.Load()
	s.mu.Lock()
	genBefore := s.rankGen
	s.mu.Unlock()

	s.healthCheck()
	// The health check reads alive state itself, so compare from after it ran.
	aliveReads := fast.aliveReads.Load() + slow.aliveReads.Load()
	s.mu.Lock()
	genAfter := s.rankGen
	s.mu.Unlock()
	s.orderedCandidates(metadata, false)

	// A rebuild alone would also be explained by the TTL on a slow machine, so the
	// generation counter is the wall-clock independent proof.
	if genAfter <= genBefore {
		t.Fatalf("a health check must invalidate the ranking: rankGen %d -> %d", genBefore, genAfter)
	}
	if got := fast.delayReads.Load() + slow.delayReads.Load(); got <= delayReads {
		t.Fatalf("a health check must invalidate the cached ranking: %d -> %d", delayReads, got)
	}
	if got := fast.aliveReads.Load() + slow.aliveReads.Load(); got <= aliveReads {
		t.Fatalf("a health check must invalidate the cached ranking: %d -> %d", aliveReads, got)
	}
}

func TestSmartOrderedCandidatesPrefersAliveOnSiteMiss(t *testing.T) {
	dead := newFakeProxy("Dead", 50)
	dead.alive = false
	alive := newFakeProxy("Alive", 500)
	s := newTestSmartWithProxies(dead, alive)

	metadata := &C.Metadata{Host: "miss.example.com"}
	now := time.Now()
	s.rememberSite(metadata, "Dead", false, now)
	s.rememberSite(metadata, "Alive", false, now)

	order := s.orderedCandidates(metadata, false)
	if len(order) != 2 {
		t.Fatalf("expected both candidates, got %d", len(order))
	}
	if order[0].Name() != "Alive" {
		t.Fatalf("the all-siteMiss fallback must pick a live candidate, got %s first", order[0].Name())
	}
	if order[1].Name() != "Dead" {
		t.Fatalf("the dead candidate must stay behind, got %s second", order[1].Name())
	}
}

func TestSmartSupportUDP(t *testing.T) {
	noUDP := newFakeProxy("NoUDP", 100)
	udp := newFakeProxy("UDP", 110)
	udp.supportUDP = true

	t.Run("one capable member", func(t *testing.T) {
		s := newTestSmartWithProxies(noUDP, udp)
		s.ForceSet("NoUDP") // the pinned policy must not decide the capability
		if !s.SupportUDP() {
			t.Fatalf("a group with one UDP-capable member must support UDP")
		}
	})

	t.Run("no capable member", func(t *testing.T) {
		s := newTestSmartWithProxies(noUDP, newFakeProxy("NoUDP2", 120))
		if s.SupportUDP() {
			t.Fatalf("a group without UDP-capable members must not support UDP")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		s := newTestSmartWithProxies(noUDP, udp)
		s.disableUDP = true
		if s.SupportUDP() {
			t.Fatalf("disableUDP must override capable members")
		}
	})
}

func TestSmartUnwrapAndIsL3ProtocolAreDeterministic(t *testing.T) {
	best := newFakeProxy("Best", 100)
	closeScore := newFakeProxy("Close", 110) // inside the preferred gap, so a random pick could flip
	closeScore.l3 = true
	s := newTestSmartWithProxies(best, closeScore)

	for i := 0; i < 64; i++ {
		if got := s.Unwrap(nil, false).Name(); got != "Best" {
			t.Fatalf("Unwrap must always return the best-scored alive member, got %s on call %d", got, i)
		}
		if s.IsL3Protocol(nil) {
			t.Fatalf("IsL3Protocol must follow the same deterministic representative on call %d", i)
		}
	}

	if err := s.Set("Close"); err != nil {
		t.Fatalf("pinning Close failed: %v", err)
	}
	for i := 0; i < 8; i++ {
		if got := s.Unwrap(nil, false).Name(); got != "Close" {
			t.Fatalf("a valid pinned member must always win, got %s on call %d", got, i)
		}
		if !s.IsL3Protocol(nil) {
			t.Fatalf("IsL3Protocol must use the pinned member on call %d", i)
		}
	}
}

func TestSmartUnwrapFallbacks(t *testing.T) {
	t.Run("pin left the group", func(t *testing.T) {
		dead := newFakeProxy("Dead", 50)
		dead.alive = false
		alive := newFakeProxy("Alive", 200)
		s := newTestSmartWithProxies(dead, alive)
		s.ForceSet("Gone")

		for i := 0; i < 8; i++ {
			if got := s.Unwrap(nil, false).Name(); got != "Alive" {
				t.Fatalf("a stale pin must fall back to the best-scored alive member, got %s", got)
			}
		}
	})

	t.Run("no alive member", func(t *testing.T) {
		slower := newFakeProxy("Slower", 400)
		slower.alive = false
		faster := newFakeProxy("Faster", 300)
		faster.alive = false
		s := newTestSmartWithProxies(slower, faster)

		for i := 0; i < 8; i++ {
			if got := s.Unwrap(nil, false).Name(); got != "Faster" {
				t.Fatalf("without alive members the best-scored member must win, got %s", got)
			}
		}
	})

	t.Run("empty group", func(t *testing.T) {
		fallback := newFakeProxy("Fallback", 100)
		s := newTestSmart()
		s.GroupBase = NewGroupBase(GroupBaseOption{
			Name:          "smart",
			Type:          C.Smart,
			TestTimeout:   1000,
			EmptyFallback: fallback,
			Providers:     []P.ProxyProvider{&fakeProvider{}},
		})
		s.testUrl = C.DefaultTestURL

		if got := s.Unwrap(nil, false); got != fallback {
			t.Fatalf("an empty group must unwrap to its fallback, got %v", got)
		}
		if s.IsL3Protocol(nil) {
			t.Fatalf("the fallback must answer L3 queries")
		}
	})
}

func TestSmartDialContextRetriesByCandidate(t *testing.T) {
	metadata := &C.Metadata{Host: "retry.example.com"}

	t.Run("not support falls through", func(t *testing.T) {
		unsupported := newFakeProxy("Unsupported", 100)
		unsupported.dialErr = C.ErrNotSupport
		working := newFakeProxy("Working", 110)
		working.dialConn = &fakeConn{}
		s := newTestSmartWithProxies(unsupported, working)
		s.ForceSet("Unsupported") // pinned first, then the rest by score

		conn, err := s.DialContext(context.Background(), metadata)
		if err != nil || conn == nil {
			t.Fatalf("the next candidate must be tried after ErrNotSupport, got conn %v err %v", conn, err)
		}
		if working.dialCalls != 1 {
			t.Fatalf("the working candidate must be dialed once, got %d", working.dialCalls)
		}
		if _, ok := s.states["Unsupported"]; ok {
			t.Fatalf("ErrNotSupport must not create node state, got %+v", s.states["Unsupported"])
		}
	})

	t.Run("node error is penalized then retried", func(t *testing.T) {
		failing := newFakeProxy("Failing", 100)
		failing.dialErr = errors.New("connection reset by peer")
		working := newFakeProxy("Working", 110)
		working.dialConn = &fakeConn{}
		s := newTestSmartWithProxies(failing, working)
		s.ForceSet("Failing")

		conn, err := s.DialContext(context.Background(), metadata)
		if err != nil || conn == nil {
			t.Fatalf("a node error must still fall back to the next candidate, got conn %v err %v", conn, err)
		}
		if st := s.states["Failing"]; st == nil || st.failStreak != 1 {
			t.Fatalf("a node error must fail the node once, got %+v", st)
		}
		if st := s.states["Working"]; st == nil || st.decayedUsage(time.Now()) <= 0 {
			t.Fatalf("the successful candidate must count as used, got %+v", st)
		}
	})

	t.Run("caller cancellation stops before dialing", func(t *testing.T) {
		stopped := newFakeProxy("Stopped", 100)
		stopped.dialErr = context.Canceled
		untried := newFakeProxy("Untried", 110)
		untried.dialConn = &fakeConn{}
		s := newTestSmartWithProxies(stopped, untried)
		s.ForceSet("Stopped")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := s.DialContext(ctx, metadata); !errors.Is(err, context.Canceled) {
			t.Fatalf("dial must return the caller cancellation, got %v", err)
		}
		if stopped.dialCalls != 0 || untried.dialCalls != 0 {
			t.Fatalf("a canceled caller must not dial, got %d and %d calls", stopped.dialCalls, untried.dialCalls)
		}
		if _, ok := s.states["Stopped"]; ok {
			t.Fatalf("caller cancellation must not create node state, got %+v", s.states["Stopped"])
		}
	})

	t.Run("node deadline is retried", func(t *testing.T) {
		stopped := newFakeProxy("Stopped", 100)
		stopped.dialErr = context.DeadlineExceeded
		working := newFakeProxy("Working", 110)
		working.dialConn = &fakeConn{}
		s := newTestSmartWithProxies(stopped, working)
		s.ForceSet("Stopped")

		conn, err := s.DialContext(context.Background(), metadata)
		if err != nil || conn == nil {
			t.Fatalf("a node deadline must fall back to the next candidate, got conn %v err %v", conn, err)
		}
		if st := s.states["Stopped"]; st == nil || st.failStreak != 1 {
			t.Fatalf("a node deadline with a live caller context must fail the node, got %+v", st)
		}
		if working.dialCalls != 1 {
			t.Fatalf("the next candidate must be dialed once, got %d", working.dialCalls)
		}
	})
}

func TestSmartDialContextRetryLimit(t *testing.T) {
	var proxies []C.Proxy
	for i := 0; i < smartDialRetryLimit+1; i++ {
		proxy := newFakeProxy(fmt.Sprintf("P%d", i), uint16(100+i))
		proxy.dialErr = errors.New("connection reset by peer")
		proxies = append(proxies, proxy)
	}
	s := newTestSmartWithProxies(proxies...)
	s.ForceSet("P0") // pinned first, then the rest by score

	if _, err := s.DialContext(context.Background(), &C.Metadata{Host: "limit.example.com"}); err == nil {
		t.Fatalf("dial must fail when every tried candidate fails")
	}
	for i, proxy := range proxies {
		want := 1
		if i >= smartDialRetryLimit {
			want = 0
		}
		if got := proxy.(*fakeProxy).dialCalls; got != want {
			t.Fatalf("P%d dialed %d times, want %d", i, got, want)
		}
	}
}

func TestSmartListenPacketSkipsNonUDPAndRetries(t *testing.T) {
	nonUDP := newFakeProxy("NonUDP", 100)
	failing := newFakeProxy("Failing", 110)
	failing.supportUDP = true
	failing.listenErr = errors.New("connection reset by peer")
	working := newFakeProxy("Working", 120)
	working.supportUDP = true

	s := newTestSmartWithProxies(nonUDP, failing, working)
	s.ForceSet("NonUDP") // pinned first, then the rest by score

	pc, err := s.ListenPacketContext(context.Background(), &C.Metadata{Host: "udp.example.com"})
	if err != nil || pc == nil {
		t.Fatalf("a working UDP candidate must be reached, got pc %v err %v", pc, err)
	}
	if nonUDP.listenCalls != 0 {
		t.Fatalf("non-UDP members must never be asked for a packet connection, got %d calls", nonUDP.listenCalls)
	}
	if failing.listenCalls != 1 || working.listenCalls != 1 {
		t.Fatalf("listen calls mismatch: failing %d working %d", failing.listenCalls, working.listenCalls)
	}
	if st := s.states["Failing"]; st == nil || st.failStreak != 1 {
		t.Fatalf("a node error must fail the UDP member, got %+v", st)
	}
	if st := s.states["Working"]; st == nil || st.decayedUsage(time.Now()) <= 0 {
		t.Fatalf("the successful UDP member must count as used, got %+v", st)
	}
	fakePC, ok := pc.(*fakePacketConn)
	if !ok || len(fakePC.chains) != 1 {
		t.Fatalf("the packet connection must be appended to the group chain, got %#v", pc)
	}
}

func TestSmartListenPacketIgnoresNonNodeErrors(t *testing.T) {
	metadata := &C.Metadata{Host: "udp.example.com"}

	t.Run("not support falls through", func(t *testing.T) {
		unsupported := newFakeProxy("Unsupported", 100)
		unsupported.supportUDP = true
		unsupported.listenErr = C.ErrNotSupport
		working := newFakeProxy("Working", 110)
		working.supportUDP = true
		s := newTestSmartWithProxies(unsupported, working)
		s.ForceSet("Unsupported")

		if pc, err := s.ListenPacketContext(context.Background(), metadata); err != nil || pc == nil {
			t.Fatalf("the next UDP candidate must be tried after ErrNotSupport, got pc %v err %v", pc, err)
		}
		if _, ok := s.states["Unsupported"]; ok {
			t.Fatalf("ErrNotSupport must not create node state, got %+v", s.states["Unsupported"])
		}
	})

	t.Run("caller cancellation stops before listening", func(t *testing.T) {
		stopped := newFakeProxy("Stopped", 100)
		stopped.supportUDP = true
		untried := newFakeProxy("Untried", 110)
		untried.supportUDP = true
		s := newTestSmartWithProxies(stopped, untried)
		s.ForceSet("Stopped")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := s.ListenPacketContext(ctx, metadata); !errors.Is(err, context.Canceled) {
			t.Fatalf("listen packet must return the caller cancellation, got %v", err)
		}
		if stopped.listenCalls != 0 || untried.listenCalls != 0 {
			t.Fatalf("a canceled caller must not listen, got %d and %d calls", stopped.listenCalls, untried.listenCalls)
		}
		if _, ok := s.states["Stopped"]; ok {
			t.Fatalf("caller cancellation must not create node state, got %+v", s.states["Stopped"])
		}
	})

	t.Run("node deadline is retried", func(t *testing.T) {
		stopped := newFakeProxy("Stopped", 100)
		stopped.supportUDP = true
		stopped.listenErr = context.DeadlineExceeded
		working := newFakeProxy("Working", 110)
		working.supportUDP = true
		s := newTestSmartWithProxies(stopped, working)
		s.ForceSet("Stopped")

		pc, err := s.ListenPacketContext(context.Background(), metadata)
		if err != nil || pc == nil {
			t.Fatalf("a node deadline must fall back to the next UDP candidate, got pc %v err %v", pc, err)
		}
		if st := s.states["Stopped"]; st == nil || st.failStreak != 1 {
			t.Fatalf("a node deadline with a live caller context must fail the node, got %+v", st)
		}
		if working.listenCalls != 1 {
			t.Fatalf("the next UDP candidate must be tried once, got %d", working.listenCalls)
		}
	})
}

func TestSmartListenPacketWithoutUDPCapability(t *testing.T) {
	nonUDP := newFakeProxy("A", 100)
	other := newFakeProxy("B", 110)
	s := newTestSmartWithProxies(nonUDP, other)

	pc, err := s.ListenPacketContext(context.Background(), &C.Metadata{Host: "udp.example.com"})
	if pc != nil || !errors.Is(err, C.ErrNotSupport) {
		t.Fatalf("a group without UDP members must report an unsupported capability, got pc %v err %v", pc, err)
	}
	if nonUDP.listenCalls != 0 || other.listenCalls != 0 {
		t.Fatalf("non-UDP members must not be dialed, got %d and %d calls", nonUDP.listenCalls, other.listenCalls)
	}
}
