package outboundgroup

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

// fakeProxy implements C.Proxy with just enough behavior for scoring tests.
type fakeProxy struct {
	name       string
	delay      uint16
	alive      bool
	supportUDP bool
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
func (f *fakeProxy) IsL3Protocol(metadata *C.Metadata) bool { return false }
func (f *fakeProxy) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return f
}
func (f *fakeProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func newTestSmart() *Smart {
	return &Smart{
		states: make(map[string]*smartPolicyState),
		sites:  make(map[string]*smartSiteRecord),
	}
}

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
	if got := st.effectiveScore(smartUnknownScore, later); got != base {
		t.Fatalf("failure penalty must expire with the cooldown, got %v base %v", got, base)
	}

	st.observeLatency(100, later)
	if st.failStreak != 0 {
		t.Fatalf("success must reset the failure streak, got %d", st.failStreak)
	}
}

func TestSmartLossPenalty(t *testing.T) {
	st := &smartPolicyState{}
	st.observeLoss(0.01)
	if math.Abs(st.lossPenalty-50) > 0.001 {
		t.Fatalf("1%% loss must add 50ms, got %v", st.lossPenalty)
	}

	st.observeLoss(0.10)
	if math.Abs(st.lossPenalty-275) > 0.001 {
		t.Fatalf("loss penalty must smooth toward the new value, got %v", st.lossPenalty)
	}

	capped := &smartPolicyState{}
	capped.observeLoss(1.0)
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
