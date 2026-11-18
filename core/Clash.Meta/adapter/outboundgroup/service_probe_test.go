package outboundgroup

import (
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

func TestSmartMergeVerdictsKeepsBlocked(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100), newFakeProxy("b", 200))
	s.service = "openai"
	now := time.Now()
	s.verdicts["a"] = serviceVerdict{at: now, known: true, blocked: true}

	s.mu.Lock()
	s.mergeVerdictsLocked(map[string]serviceVerdict{
		// A 429, a 5xx or a challenge page says nothing about the member, so the
		// demotion stays until it expires on its own TTL.
		"a": {at: now},
		// A decidable answer is still recorded.
		"b": {at: now, known: true, blocked: true},
	})
	blockedA := s.serviceBlockedLocked("a", now)
	blockedB := s.serviceBlockedLocked("b", now)
	s.mu.Unlock()

	if !blockedA {
		t.Fatal("an undecidable probe must not lift the previous blocked verdict")
	}
	if !blockedB {
		t.Fatal("a known blocked verdict must be recorded")
	}

	s.mu.Lock()
	s.mergeVerdictsLocked(map[string]serviceVerdict{"a": {at: now, known: true}})
	cleared := s.serviceBlockedLocked("a", now)
	s.mu.Unlock()
	if cleared {
		t.Fatal("a known allowed verdict must lift the demotion")
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
