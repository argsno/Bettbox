package outboundgroup

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestNormalizeServiceName(t *testing.T) {
	cases := map[string]string{
		"":               "",
		"openai":         "openai",
		"OpenAI":         "openai",
		" chatgpt ":      "openai",
		" gemini ":       "google-gemini",
		"google-gemini":  "google-gemini",
		"youtube":        "youtube",
		"YouTube":        "youtube",
		"google-youtube": "youtube",
	}
	for input, want := range cases {
		got, err := normalizeServiceName(input)
		if err != nil {
			t.Fatalf("%q: unexpected error %v", input, err)
		}
		if got != want {
			t.Fatalf("%q: got %q, want %q", input, got, want)
		}
	}
	if _, err := normalizeServiceName("claude"); err == nil {
		t.Fatal("unknown service must be rejected")
	}
}

func TestParseTraceBody(t *testing.T) {
	body := strings.Join([]string{
		"fl=1abc",
		"ip=203.0.113.7",
		"loc=HK",
		"colo=HKG",
		"warp=on",
		"",
	}, "\n")
	ip, loc, colo, warp := parseTraceBody(body)
	if ip != "203.0.113.7" || loc != "HK" || colo != "HKG" || !warp {
		t.Fatalf("parsed ip=%q loc=%q colo=%q warp=%v", ip, loc, colo, warp)
	}
}

func TestEvaluateOpenAITrace(t *testing.T) {
	preset := servicePresets["openai"]

	blocked := evaluateServiceResponse(preset, 200, "", "ip=1.2.3.4\nloc=HK\nwarp=off\n")
	if !blocked.known || !blocked.blocked || blocked.region != "HK" {
		t.Fatalf("HK must be blocked, got %+v", blocked)
	}

	allowed := evaluateServiceResponse(preset, 200, "", "ip=1.2.3.4\nloc=US\nwarp=off\n")
	if !allowed.known || allowed.blocked || allowed.region != "US" {
		t.Fatalf("US must be allowed, got %+v", allowed)
	}

	// No ip means Cloudflare answered with something else (challenge, block
	// page); the policy keeps its normal score instead of being demoted.
	unknown := evaluateServiceResponse(preset, 403, "", "<!DOCTYPE html>")
	if unknown.known {
		t.Fatalf("challenge response must stay unknown, got %+v", unknown)
	}
}

func TestEvaluateGeminiPage(t *testing.T) {
	preset := servicePresets["google-gemini"]

	allowed := evaluateServiceResponse(preset, 200, "https://gemini.google.com/app", `ig,2,1,200,"USA",null`)
	if !allowed.known || allowed.blocked || allowed.region != "USA" {
		t.Fatalf("US page must be allowed, got %+v", allowed)
	}

	blockedRegion := evaluateServiceResponse(preset, 200, "https://gemini.google.com/app", `ig,2,1,200,"CHN",null`)
	if !blockedRegion.blocked {
		t.Fatalf("CHN page must be blocked, got %+v", blockedRegion)
	}

	redirected := evaluateServiceResponse(preset, 200, "https://sorry.google.com/sorry/index", "")
	if !redirected.blocked {
		t.Fatalf("sorry.google.com must be blocked, got %+v", redirected)
	}

	unavailable := evaluateServiceResponse(preset, 200, "https://gemini.google.com/app", "Gemini is not supported in your country")
	if !unavailable.blocked {
		t.Fatalf("unavailable page must be blocked, got %+v", unavailable)
	}

	errorStatus := evaluateServiceResponse(preset, 503, "https://gemini.google.com/app", "")
	if errorStatus.known || errorStatus.blocked {
		t.Fatalf("a 5xx answer is undecidable, got %+v", errorStatus)
	}

	rateLimited := evaluateServiceResponse(preset, 429, "https://gemini.google.com/app", "")
	if rateLimited.known || rateLimited.blocked {
		t.Fatalf("a 429 answer is undecidable, got %+v", rateLimited)
	}

	forbidden := evaluateServiceResponse(preset, 403, "https://gemini.google.com/app", "")
	if !forbidden.known || !forbidden.blocked {
		t.Fatalf("an anti-bot page must count as unusable, got %+v", forbidden)
	}
}

func TestEvaluateYouTubePage(t *testing.T) {
	preset := servicePresets["youtube"]

	allowed := evaluateServiceResponse(preset, 200, "https://www.youtube.com/premium", `"INNERTUBE_CONTEXT_GL":"US"`)
	if !allowed.known || allowed.blocked || allowed.region != "US" {
		t.Fatalf("a US page must be allowed, got %+v", allowed)
	}

	// The media panel flags a missing Premium subscription, but videos still
	// play there; routing must not demote the member for that.
	premium := evaluateServiceResponse(preset, 200, "https://www.youtube.com/premium", "Premium is not available in your country")
	if !premium.known || premium.blocked {
		t.Fatalf("a missing Premium offer must not demote the member, got %+v", premium)
	}

	redirected := evaluateServiceResponse(preset, 200, "https://sorry.google.com/sorry/index", "")
	if !redirected.blocked {
		t.Fatalf("sorry.google.com must be blocked, got %+v", redirected)
	}

	cnRedirect := evaluateServiceResponse(preset, 200, "https://www.google.cn/", "")
	if !cnRedirect.blocked {
		t.Fatalf("a www.google.cn redirect must be blocked, got %+v", cnRedirect)
	}

	cnBody := evaluateServiceResponse(preset, 200, "https://www.youtube.com/premium", "<a href='https://www.google.cn/'>YouTube</a>")
	if !cnBody.blocked {
		t.Fatalf("a www.google.cn body must be blocked, got %+v", cnBody)
	}

	unavailable := evaluateServiceResponse(preset, 200, "https://www.youtube.com/premium", "YouTube isn't available in your country")
	if !unavailable.blocked {
		t.Fatalf("an unavailable page must be blocked, got %+v", unavailable)
	}

	errorStatus := evaluateServiceResponse(preset, 503, "https://www.youtube.com/premium", "")
	if errorStatus.known || errorStatus.blocked {
		t.Fatalf("a 5xx answer is undecidable, got %+v", errorStatus)
	}

	rateLimited := evaluateServiceResponse(preset, 429, "https://www.youtube.com/premium", "")
	if rateLimited.known || rateLimited.blocked {
		t.Fatalf("a 429 answer is undecidable, got %+v", rateLimited)
	}

	forbidden := evaluateServiceResponse(preset, 403, "https://www.youtube.com/premium", "")
	if !forbidden.known || !forbidden.blocked {
		t.Fatalf("a 403 page must count as unusable, got %+v", forbidden)
	}
}

func TestSmartServiceBlockedVerdict(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100), newFakeProxy("b", 200))
	s.service = "openai"
	s.verdicts["a"] = serviceVerdict{at: time.Now(), known: true, blocked: true}

	s.mu.Lock()
	blocked := s.serviceBlockedLocked("a", time.Now())
	stale := func() bool {
		s.verdicts["b"] = serviceVerdict{
			at:      time.Now().Add(-serviceVerdictTTL - time.Minute),
			known:   true,
			blocked: true,
		}
		return s.serviceBlockedLocked("b", time.Now())
	}()
	s.mu.Unlock()

	if !blocked {
		t.Fatal("fresh blocked verdict must demote the member")
	}
	if stale {
		t.Fatal("an expired verdict must stop demoting the member")
	}
}

func TestSmartApplyProbeOutcomes(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100), newFakeProxy("b", 200))
	s.service = "openai"
	now := time.Now()
	s.verdicts["a"] = serviceVerdict{at: now, known: true, blocked: true}

	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{
		// A 429, a 5xx or a challenge page says nothing about the member, so
		// the demotion stays until it expires on its own TTL; only the attempt
		// is recorded to pace the retry.
		"a": {done: true, verdict: serviceVerdict{at: now}},
		// A failed request records the attempt without touching the verdict.
		"b": {},
	}, s.Proxies(), now)
	blockedA := s.serviceBlockedLocked("a", now)
	attemptA := s.attempts["a"]
	attemptB := s.attempts["b"]
	s.mu.Unlock()

	if !blockedA {
		t.Fatal("an undecidable probe must not lift the previous blocked verdict")
	}
	if attemptA.at.IsZero() || attemptB.at.IsZero() {
		t.Fatal("every probed member must record an attempt, verdict or not")
	}
	if attemptA.misses != 1 || attemptB.misses != 1 {
		t.Fatalf("an undecidable answer and a failed request must each count a miss, got %d and %d", attemptA.misses, attemptB.misses)
	}

	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{
		"a": {done: true, verdict: serviceVerdict{at: now, known: true}},
		"b": {done: true, verdict: serviceVerdict{at: now, known: true, blocked: true}},
	}, s.Proxies(), now)
	clearedA := s.serviceBlockedLocked("a", now)
	blockedB := s.serviceBlockedLocked("b", now)
	missesA := s.attempts["a"].misses
	missesB := s.attempts["b"].misses
	s.mu.Unlock()
	if clearedA {
		t.Fatal("a known allowed verdict must lift the demotion")
	}
	if !blockedB {
		t.Fatal("a known blocked verdict must be recorded")
	}
	if missesA != 0 || missesB != 0 {
		t.Fatalf("a decidable answer must reset the miss streak, got %d and %d", missesA, missesB)
	}
}

func TestSmartApplyProbeOutcomesPrunesGoneMembers(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100))
	s.service = "openai"
	now := time.Now()
	s.verdicts["ghost"] = serviceVerdict{at: now, known: true, blocked: true}
	s.attempts["ghost"] = serviceProbeAttempt{at: now, misses: 2}

	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{
		"ghost": {done: true, verdict: serviceVerdict{at: now, known: true}},
	}, s.Proxies(), now)
	s.mu.Unlock()

	if _, ok := s.verdicts["ghost"]; ok {
		t.Fatal("a verdict for a member that left the group must be dropped")
	}
	if _, ok := s.attempts["ghost"]; ok {
		t.Fatal("an attempt for a member that left the group must be dropped")
	}
}

func TestSmartSelectServiceProbeMembers(t *testing.T) {
	alive := newFakeProxy("Alive", 100)
	slow := newFakeProxy("Slow", 300)
	dead := newFakeProxy("Dead", 50)
	dead.alive = false
	s := newTestSmartWithProxies(alive, slow, dead)
	s.service = "openai"
	now := time.Now()

	selectNames := func() []string {
		s.mu.Lock()
		defer s.mu.Unlock()
		return names(s.selectServiceProbeMembersLocked(s.Proxies(), now))
	}

	// Bootstrap: no verdict exists, so every alive member is probed at once.
	if got, want := selectNames(), []string{"Alive", "Slow"}; !slices.Equal(got, want) {
		t.Fatalf("bootstrap must probe every alive member, want %v got %v", want, got)
	}

	// A fresh verdict takes the member out until the refresh window lapses.
	s.mu.Lock()
	s.verdicts["Alive"] = serviceVerdict{at: now, known: true}
	s.mu.Unlock()
	if got, want := selectNames(), []string{"Slow"}; !slices.Equal(got, want) {
		t.Fatalf("a fresh verdict must exclude the member, want %v got %v", want, got)
	}

	// A recent attempt that produced no verdict backs the member off.
	s.mu.Lock()
	s.attempts["Slow"] = serviceProbeAttempt{at: now}
	s.mu.Unlock()
	if got := selectNames(); len(got) != 0 {
		t.Fatalf("a recent failed attempt must back the member off, got %v", got)
	}

	// Two consecutive misses double the backoff to ten minutes: six minutes
	// after the last attempt the member is still waiting, where the flat
	// five-minute window would already have let it back.
	s.mu.Lock()
	s.attempts["Slow"] = serviceProbeAttempt{at: now.Add(-6 * time.Minute), misses: 2}
	s.verdicts["Alive"] = serviceVerdict{at: now, known: true}
	s.mu.Unlock()
	if got := selectNames(); len(got) != 0 {
		t.Fatalf("a doubled backoff must keep the member waiting, got %v", got)
	}

	// Once the backoff window lapses, the member returns.
	s.mu.Lock()
	s.attempts["Slow"] = serviceProbeAttempt{at: now.Add(-2*serviceProbeRetry - time.Minute)}
	s.verdicts["Alive"] = serviceVerdict{at: now.Add(-serviceVerdictRefresh - time.Second), known: true}
	s.mu.Unlock()
	if got, want := selectNames(), []string{"Alive", "Slow"}; !slices.Equal(got, want) {
		t.Fatalf("stale verdicts must be re-probed, want %v got %v", want, got)
	}
}

func TestSmartSelectServiceProbeMembersBatchCap(t *testing.T) {
	var proxies []C.Proxy
	for i := 0; i < 20; i++ {
		proxies = append(proxies, newFakeProxy(fmt.Sprintf("P%02d", i), uint16(100+i*50)))
	}
	s := newTestSmartWithProxies(proxies...)
	s.service = "youtube"
	now := time.Now()
	// One member is already fresh, so the run is incremental and capped.
	s.verdicts["P00"] = serviceVerdict{at: now, known: true}

	s.mu.Lock()
	selected := s.selectServiceProbeMembersLocked(s.Proxies(), now)
	s.mu.Unlock()
	if len(selected) != serviceProbeBatch {
		t.Fatalf("an incremental run must cap at %d members, got %d", serviceProbeBatch, len(selected))
	}
	for _, proxy := range selected {
		if proxy.Name() == "P19" {
			t.Fatal("the worst-scored tail must wait for a later run")
		}
	}

	// The cap lifts only when no fresh verdict exists at all.
	s.mu.Lock()
	delete(s.verdicts, "P00")
	full := s.selectServiceProbeMembersLocked(s.Proxies(), now)
	s.mu.Unlock()
	if len(full) != 20 {
		t.Fatalf("a bootstrap run must sweep every alive member, got %d", len(full))
	}
}

func TestSmartMaybeProbeServiceSkipsWhenNothingStale(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100), newFakeProxy("b", 200))
	s.service = "openai"
	now := time.Now()
	s.verdicts["a"] = serviceVerdict{at: now, known: true}
	s.verdicts["b"] = serviceVerdict{at: now, known: true}

	s.maybeProbeService(s.Proxies())

	s.mu.Lock()
	probing := s.probing
	lastProbe := s.lastProbe
	s.mu.Unlock()
	if probing || !lastProbe.IsZero() {
		t.Fatalf("nothing to learn must not start a run, probing=%t lastProbe=%v", probing, lastProbe)
	}
}

func TestSmartOrderedCandidatesSkipsBlocked(t *testing.T) {
	dead := newFakeProxy("dead", 50)
	dead.alive = false
	s := newTestSmartWithProxies(
		newFakeProxy("a", 100),
		newFakeProxy("b", 200),
		newFakeProxy("c", 300),
		dead,
	)
	s.service = "openai"
	// "a" is the fastest live member, so only the service verdict can push it
	// back; the dead member sorts first on score alone.
	s.verdicts["a"] = serviceVerdict{at: time.Now(), known: true, blocked: true}
	// The ordering does not need a probe, and one would dial the service for real.
	s.lastProbe = time.Now()

	order := s.orderedCandidates(&C.Metadata{Host: "chatgpt.com"}, false)
	if len(order) != 4 {
		t.Fatalf("expected every member to stay dialable, got %d", len(order))
	}
	if order[0].Name() == "a" {
		t.Fatalf("blocked member must not be picked first: %v", names(order))
	}
	if got, want := names(order), []string{"b", "c", "a", "dead"}; !slices.Equal(got, want) {
		t.Fatalf("healthy, then service-blocked, then dead expected %v, got %v", want, got)
	}
}

func TestSmartBlockedMemberBeatsDeadFirstPick(t *testing.T) {
	dead := newFakeProxy("dead", 50)
	dead.alive = false
	s := newTestSmartWithProxies(
		dead,
		newFakeProxy("a", 100),
		newFakeProxy("b", 200),
	)
	s.service = "openai"
	s.verdicts["a"] = serviceVerdict{at: time.Now(), known: true, blocked: true}
	s.verdicts["b"] = serviceVerdict{at: time.Now(), known: true, blocked: true}
	s.lastProbe = time.Now()

	// Every live member is service-blocked, so the first pick falls back to a
	// blocked member instead of the faster dead one.
	order := s.orderedCandidates(&C.Metadata{Host: "chatgpt.com"}, false)
	if got, want := names(order), []string{"a", "b", "dead"}; !slices.Equal(got, want) {
		t.Fatalf("a live-but-blocked member must be tried before a dead one: want %v, got %v", want, got)
	}
}

func TestSmartServiceGroupSticksToRecentSiteMember(t *testing.T) {
	best := newFakeProxy("Best", 100)
	recent := newFakeProxy("Recent", 130) // inside the widened hit band
	s := newTestSmartWithProxies(best, recent)
	s.service = "openai"
	metadata := &C.Metadata{Host: "sticky.example.com"}
	now := time.Now()
	s.rememberSite(metadata, "Recent", true, now.Add(-time.Minute))
	s.lastProbe = now // the ordering itself must not start a probe run

	for i := 0; i < 32; i++ {
		order := s.orderedCandidates(metadata, false)
		if len(order) != 2 || order[0].Name() != "Recent" {
			t.Fatalf("the recent site member must stay the first pick, got %v on call %d", names(order), i)
		}
	}
}

func TestSmartStickyPickTakesMostRecentSuccess(t *testing.T) {
	a := newFakeProxy("A", 100)
	b := newFakeProxy("B", 110)
	s := newTestSmartWithProxies(a, b)
	s.service = "youtube"
	metadata := &C.Metadata{Host: "recent-wins.example.com"}
	now := time.Now()
	s.rememberSite(metadata, "A", true, now.Add(-2*time.Minute))
	s.rememberSite(metadata, "B", true, now.Add(-time.Minute))
	s.lastProbe = now

	for i := 0; i < 16; i++ {
		if order := s.orderedCandidates(metadata, false); order[0].Name() != "B" {
			t.Fatalf("the most recent success must win, got %v", names(order))
		}
	}
}

func TestSmartStickyMemberOutOfBandIsNotPinned(t *testing.T) {
	best := newFakeProxy("Best", 100)
	degraded := newFakeProxy("Degraded", 300) // 3x the best: outside even the hit band
	s := newTestSmartWithProxies(best, degraded)
	s.service = "openai"
	metadata := &C.Metadata{Host: "out-of-band.example.com"}
	now := time.Now()
	s.rememberSite(metadata, "Degraded", true, now.Add(-time.Minute))
	s.lastProbe = now

	for i := 0; i < 8; i++ {
		if order := s.orderedCandidates(metadata, false); order[0].Name() != "Best" {
			t.Fatalf("an out-of-band member must not be pinned, got %v", names(order))
		}
	}
}

func TestSmartStickyMemberSkipsServiceBlockedAndSiteMiss(t *testing.T) {
	metadata := &C.Metadata{Host: "sticky-edge.example.com"}
	now := time.Now()

	t.Run("service-blocked verdict", func(t *testing.T) {
		blocked := newFakeProxy("Blocked", 100)
		other := newFakeProxy("Other", 110)
		s := newTestSmartWithProxies(blocked, other)
		s.service = "openai"
		s.verdicts["Blocked"] = serviceVerdict{at: now, known: true, blocked: true}
		s.rememberSite(metadata, "Blocked", true, now.Add(-time.Minute))
		s.lastProbe = now

		if order := s.orderedCandidates(metadata, false); order[0].Name() == "Blocked" {
			t.Fatalf("a service-blocked member must not be pinned, got %v", names(order))
		}
	})

	t.Run("fresh site failure", func(t *testing.T) {
		failing := newFakeProxy("Failing", 100)
		other := newFakeProxy("Other", 110)
		s := newTestSmartWithProxies(failing, other)
		s.service = "openai"
		s.rememberSite(metadata, "Failing", true, now.Add(-2*time.Minute))
		s.rememberSite(metadata, "Failing", false, now.Add(-time.Minute))
		s.lastProbe = now

		if order := s.orderedCandidates(metadata, false); order[0].Name() == "Failing" {
			t.Fatalf("a member that just failed the site must not be pinned, got %v", names(order))
		}
	})
}

func TestSmartGeneralGroupKeepsRotation(t *testing.T) {
	a := newFakeProxy("A", 100)
	b := newFakeProxy("B", 110)
	s := newTestSmartWithProxies(a, b) // service stays empty: rotation is the point
	metadata := &C.Metadata{Host: "rotate.example.com"}
	s.rememberSite(metadata, "B", true, time.Now())

	seen := make(map[string]bool, 2)
	for i := 0; i < 200; i++ {
		seen[s.orderedCandidates(metadata, false)[0].Name()] = true
	}
	if !seen["A"] || !seen["B"] {
		t.Fatalf("a general group must keep rotating inside the band, saw %v", seen)
	}
}

func names(proxies []C.Proxy) []string {
	out := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		out = append(out, proxy.Name())
	}
	return out
}

func TestNewSmartServiceOption(t *testing.T) {
	// An unknown value only disables the ranking: a synced script must not be
	// able to break a config whose core predates the option.
	fallback, err := NewSmart(GroupCommonOption{Name: "smart"}, SmartOption{Service: "claude"}, nil, nil)
	if err != nil {
		t.Fatalf("unknown service must not fail the config: %v", err)
	}
	if fallback.service != "" {
		t.Fatalf("unknown service must be dropped, got %q", fallback.service)
	}

	s, err := NewSmart(GroupCommonOption{Name: "smart"}, SmartOption{Service: "gemini"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.service != "google-gemini" {
		t.Fatalf("service alias not normalized: %q", s.service)
	}

	y, err := NewSmart(GroupCommonOption{Name: "smart"}, SmartOption{Service: "YouTube"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if y.service != "youtube" {
		t.Fatalf("service alias not normalized: %q", y.service)
	}
}

func TestSmartServiceProbeBackoffSchedule(t *testing.T) {
	cases := []struct {
		misses int
		want   time.Duration
	}{
		{0, serviceProbeRetry},
		{1, serviceProbeRetry},
		{2, 2 * serviceProbeRetry},
		{3, 4 * serviceProbeRetry},
		{4, serviceProbeRetryMax},
		{5, serviceProbeRetryMax},
		{6, serviceProbeRetryMax},
		{9, serviceProbeRetryMax},
	}
	for _, tc := range cases {
		if got := (serviceProbeAttempt{misses: tc.misses}).backoff(); got != tc.want {
			t.Fatalf("backoff(%d) = %v, want %v", tc.misses, got, tc.want)
		}
	}
}

func TestSmartBlockedVerdictTrustedDuringBackoff(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100))
	s.service = "openai"
	now := time.Now()

	// A fresh blocked verdict demotes as usual.
	fresh := serviceVerdict{at: now, known: true, blocked: true}
	// The blocked verdict is older than its TTL, but the member's probes keep
	// failing to produce a decidable answer: the demotion must persist.
	expired := serviceVerdict{at: now.Add(-serviceVerdictTTL - time.Minute), known: true, blocked: true}
	s.mu.Lock()
	s.verdicts["a"] = fresh
	trusted := s.serviceBlockedLocked("a", now)
	s.verdicts["a"] = expired
	s.attempts["a"] = serviceProbeAttempt{at: now.Add(-time.Minute), misses: 2}
	trustedDuringBackoff := s.serviceBlockedLocked("a", now)
	s.attempts["a"] = serviceProbeAttempt{at: now.Add(-serviceProbeRetryMax - time.Minute), misses: 2}
	lapsed := s.serviceBlockedLocked("a", now)
	// An allowed verdict gets no such extension: an expired allowed member is
	// simply no longer boosted, and misses never demote it.
	s.verdicts["a"] = serviceVerdict{at: expired.at, known: true}
	allowed := s.serviceBlockedLocked("a", now)
	s.mu.Unlock()

	if !trusted {
		t.Fatal("test setup: a fresh blocked verdict must demote")
	}
	if !trustedDuringBackoff {
		t.Fatal("an expired blocked verdict must stay trusted while the probe keeps failing")
	}
	if lapsed {
		t.Fatal("the extended trust must lapse with the backoff window")
	}
	if allowed {
		t.Fatal("an expired allowed verdict must never demote, misses or not")
	}
}
