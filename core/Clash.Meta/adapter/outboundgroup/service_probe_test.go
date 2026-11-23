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

	// The app's unlock panel already treats the /unavailable redirect as a
	// refusal; the core ranks members by the same policy.
	unavailablePath := evaluateServiceResponse(preset, 200, "https://gemini.google.com/unavailable", "<html>Gemini</html>")
	if !unavailablePath.blocked {
		t.Fatalf("the unavailable path must be blocked, got %+v", unavailablePath)
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

func TestServicePresetBodyLimits(t *testing.T) {
	// The Gemini region payload sits past 800 KB of a ~1 MB page; reading only
	// the default prefix silently leaves every verdict without a region.
	if got := serviceBodyLimit(servicePresets["google-gemini"]); got <= int64(serviceProbeMaxBody) {
		t.Fatalf("gemini probe must read past the default body cap, got %d", got)
	}
	if got := serviceBodyLimit(servicePresets["openai"]); got != int64(serviceProbeMaxBody) {
		t.Fatalf("a preset without its own cap must use the default, got %d", got)
	}
}

func TestServicePresetSkipBody(t *testing.T) {
	// The YouTube body judgment is paused (see the preset comment): the probe
	// must not pay for the ~1 MB page while the result cannot change.
	if !servicePresets["youtube"].skipBody {
		t.Fatal("youtube probe must skip the body while its body judgment is paused")
	}
	if servicePresets["google-gemini"].skipBody {
		t.Fatal("gemini must read the body to extract the region")
	}
	if servicePresets["openai"].skipBody {
		t.Fatal("the openai trace lives in the body")
	}
}

func TestReadServiceBodyStopsAtRegion(t *testing.T) {
	preset := servicePresets["google-gemini"]
	body := strings.Repeat("x", 100<<10) + `,2,1,200,"USA"` + strings.Repeat("y", 200<<10)

	got, err := readServiceBody(preset, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `,2,1,200,"USA"`) {
		t.Fatalf("the region marker must survive the read, got %d bytes", len(got))
	}
	if len(got) >= len(body) {
		t.Fatalf("the scan must stop at the marker, read %d of %d bytes", len(got), len(body))
	}
}

func TestReadServiceBodyFindsPatternAcrossChunks(t *testing.T) {
	preset := servicePresets["google-gemini"]
	prefix := strings.Repeat("x", serviceBodyChunk-8)
	body := prefix + `,2,1,200,"USA"` + strings.Repeat("y", 100<<10)

	got, err := readServiceBody(preset, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `,2,1,200,"USA"`) {
		t.Fatalf("a pattern across the chunk boundary must be found, got %d bytes", len(got))
	}
	if len(got) >= len(body) {
		t.Fatalf("the scan must stop at the marker, read %d of %d bytes", len(got), len(body))
	}
}

func TestReadServiceBodyCapsWithoutMatch(t *testing.T) {
	preset := servicePresets["openai"]
	body := strings.Repeat("x", int(serviceProbeMaxBody)+1024)

	got, err := readServiceBody(preset, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(got)) != int64(serviceProbeMaxBody) {
		t.Fatalf("a body without a marker must stop at the cap, got %d bytes", len(got))
	}
}

func TestReadServiceBodyKeepsUnmatchedBody(t *testing.T) {
	preset := servicePresets["google-gemini"]
	body := strings.Repeat("x", 100<<10)

	got, err := readServiceBody(preset, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(body) {
		t.Fatalf("an unmatched body must be read whole, got %d of %d bytes", len(got), len(body))
	}
}

func TestEvaluateYouTubePage(t *testing.T) {
	// The preset's body judgment is paused (skipBody), but its rules stay in the
	// preset for the restart; this test keeps them honest until they are wired
	// back on.
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
	blocked := s.serviceUnusableLocked("a", time.Now())
	stale := func() bool {
		s.verdicts["b"] = serviceVerdict{
			at:      time.Now().Add(-serviceVerdictTTL - time.Minute),
			known:   true,
			blocked: true,
		}
		return s.serviceUnusableLocked("b", time.Now())
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
	}, s.Proxies(), now, false)
	blockedA := s.serviceUnusableLocked("a", now)
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
	if attemptA.fails != 0 || attemptB.fails != 1 {
		t.Fatalf("only the missing answer must count a transport failure, got %d and %d", attemptA.fails, attemptB.fails)
	}

	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{
		"a": {done: true, verdict: serviceVerdict{at: now, known: true}},
		"b": {done: true, verdict: serviceVerdict{at: now, known: true, blocked: true}},
	}, s.Proxies(), now, false)
	clearedA := s.serviceUnusableLocked("a", now)
	blockedB := s.serviceUnusableLocked("b", now)
	missesA := s.attempts["a"].misses
	missesB := s.attempts["b"].misses
	failsA := s.attempts["a"].fails
	failsB := s.attempts["b"].fails
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
	if failsA != 0 || failsB != 0 {
		t.Fatalf("an answered probe must reset the failure streak, got %d and %d", failsA, failsB)
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
	}, s.Proxies(), now, false)
	s.mu.Unlock()

	if _, ok := s.verdicts["ghost"]; ok {
		t.Fatal("a verdict for a member that left the group must be dropped")
	}
	if _, ok := s.attempts["ghost"]; ok {
		t.Fatal("an attempt for a member that left the group must be dropped")
	}
}

func TestSmartServiceVerified(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100))
	s.service = "google-gemini"
	now := time.Now()
	s.verdicts["a"] = serviceVerdict{at: now, known: true}

	s.mu.Lock()
	verified := s.serviceVerifiedLocked("a", now)
	s.attempts["a"] = serviceProbeAttempt{at: now, fails: 1, misses: 1}
	afterFailure := s.serviceVerifiedLocked("a", now)
	s.attempts["a"] = serviceProbeAttempt{at: now}
	expired := s.serviceVerifiedLocked("a", now.Add(serviceVerdictTTL+time.Minute))
	s.verdicts["a"] = serviceVerdict{at: now, known: true, blocked: true}
	blocked := s.serviceVerifiedLocked("a", now)
	s.verdicts["a"] = serviceVerdict{at: now}
	unknown := s.serviceVerifiedLocked("a", now)
	s.mu.Unlock()

	if !verified {
		t.Fatal("a fresh allowed verdict must confirm the member")
	}
	if afterFailure {
		t.Fatal("a request without an answer must drop the confirmation")
	}
	if expired {
		t.Fatal("a verdict older than the TTL must not confirm the member")
	}
	if blocked {
		t.Fatal("a blocked verdict must never confirm the member")
	}
	if unknown {
		t.Fatal("an undecidable verdict must not confirm the member")
	}
}

func TestSmartForceServiceProbeTargets(t *testing.T) {
	healthy := newFakeProxy("Healthy", 100)
	blocked := newFakeProxy("Blocked", 200)
	demoted := newFakeProxy("Demoted", 300)
	dead := newFakeProxy("Dead", 50)
	dead.alive = false
	s := newTestSmartWithProxies(healthy, blocked, demoted, dead)
	s.service = "google-gemini"
	now := time.Now()
	s.verdicts["Healthy"] = serviceVerdict{at: now, known: true}
	s.verdicts["Blocked"] = serviceVerdict{at: now, known: true, blocked: true}
	s.attempts["Demoted"] = serviceProbeAttempt{at: now, fails: serviceProbeFailLimit, misses: serviceProbeFailLimit}
	s.verdicts["Dead"] = serviceVerdict{at: now, known: true, blocked: true}

	s.mu.Lock()
	targets := s.forceProbeTargetsLocked(s.Proxies(), []string{"Healthy", "Blocked", "Demoted", "Dead", "Stranger"}, "", now)
	s.mu.Unlock()

	// Only demoted, alive members are re-tested; the healthy one has nothing to
	// prove and the dead one just failed the URL test that triggered the call.
	if got, want := names(targets), []string{"Blocked", "Demoted"}; !slices.Equal(got, want) {
		t.Fatalf("want %v got %v", want, got)
	}
}

func TestSmartForceServiceProbeIncludesCurrent(t *testing.T) {
	current := newFakeProxy("Current", 900)
	healthy := newFakeProxy("Healthy", 100)
	s := newTestSmartWithProxies(current, healthy)
	s.service = "google-gemini"
	now := time.Now()
	s.verdicts["Current"] = serviceVerdict{at: now, known: true}
	s.verdicts["Healthy"] = serviceVerdict{at: now, known: true}

	s.mu.Lock()
	targets := s.forceProbeTargetsLocked(s.Proxies(), []string{"Current", "Healthy"}, "Current", now)
	s.mu.Unlock()

	// The current member is confirmed, but a manual re-test must judge it again
	// so a failure can move the group; the other confirmed member is skipped.
	if got, want := names(targets), []string{"Current"}; !slices.Equal(got, want) {
		t.Fatalf("want %v got %v", want, got)
	}

	s.mu.Lock()
	foreign := s.forceProbeTargetsLocked(s.Proxies(), []string{"Healthy"}, "Current", now)
	s.mu.Unlock()
	if len(foreign) != 0 {
		t.Fatalf("the current member must not be probed when it was not tested, got %v", names(foreign))
	}
}

func TestSmartForceServiceProbeKeepsCurrentUnderCap(t *testing.T) {
	current := newFakeProxy("Current", 5000) // worst score: the cap must not drop it
	proxies := []C.Proxy{current}
	tested := []string{"Current"}
	for i := 0; i < serviceProbeBatch; i++ {
		name := fmt.Sprintf("P%02d", i)
		proxies = append(proxies, newFakeProxy(name, uint16(100+i*10)))
		tested = append(tested, name)
	}
	s := newTestSmartWithProxies(proxies...)
	s.service = "google-gemini"
	now := time.Now()
	s.verdicts["Current"] = serviceVerdict{at: now, known: true}
	for _, name := range tested[1:] {
		s.verdicts[name] = serviceVerdict{at: now, known: true, blocked: true}
	}

	s.mu.Lock()
	targets := s.forceProbeTargetsLocked(s.Proxies(), tested, "Current", now)
	s.mu.Unlock()

	if len(targets) != serviceProbeBatch {
		t.Fatalf("want %d targets, got %v", serviceProbeBatch, names(targets))
	}
	if targets[0].Name() != "Current" {
		t.Fatalf("the current member must keep the first slot, got %v", names(targets))
	}
}

func TestSmartForceServiceProbeQueuesWhileProbing(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100))
	s.service = "google-gemini"
	s.probing = true

	s.ForceServiceProbe([]string{"a"})

	s.mu.Lock()
	_, queued := s.forcePending["a"]
	probing := s.probing
	s.mu.Unlock()
	if !queued {
		t.Fatal("a re-test request during a run must be queued")
	}
	if !probing {
		t.Fatal("the in-flight run must be left alone")
	}
}

func TestSmartStartPendingProbeDropsProbedMembers(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100))
	s.service = "google-gemini"
	s.forcePending = map[string]struct{}{"a": {}}

	s.mu.Lock()
	// The finished run already covered "a", so nothing is left to queue.
	s.startPendingProbeLocked(s.Proxies(), s.Proxies())
	s.mu.Unlock()

	if s.forcePending != nil {
		t.Fatalf("a member the run just probed must be dropped, got %v", s.forcePending)
	}
}

func TestSmartRepeatedProbeFailuresDemote(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100))
	s.service = "google-gemini"
	now := time.Now()
	// The last real answer allowed the member, but it is old enough that the
	// probes are the only current evidence.
	s.verdicts["a"] = serviceVerdict{at: now.Add(-serviceVerdictTTL - time.Minute), known: true}

	s.mu.Lock()
	for i := 0; i < serviceProbeFailLimit; i++ {
		s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{"a": {}}, s.Proxies(), now, false)
	}
	demoted := s.serviceUnusableLocked("a", now)
	attempt := s.attempts["a"]
	s.mu.Unlock()

	if !demoted {
		t.Fatalf("a member that never answers must not stay usable, attempt=%+v", attempt)
	}
	if attempt.fails != serviceProbeFailLimit {
		t.Fatalf("expected %d consecutive failures, got %d", serviceProbeFailLimit, attempt.fails)
	}

	// A response, even an undecidable one, proves the egress reaches the
	// service and clears the failure streak on the next run.
	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{"a": {done: true}}, s.Proxies(), now, false)
	recovered := !s.serviceUnusableLocked("a", now)
	fails := s.attempts["a"].fails
	s.mu.Unlock()
	if !recovered {
		t.Fatal("an answered probe must lift the failure demotion")
	}
	if fails != 0 {
		t.Fatalf("an answered probe must reset the failure streak, got %d", fails)
	}
}

func TestSmartForcedProbeDemotesImmediately(t *testing.T) {
	failed := newFakeProxy("failed", 100)
	silent := newFakeProxy("silent", 200)
	s := newTestSmartWithProxies(failed, silent)
	s.service = "google-gemini"
	now := time.Now()
	s.verdicts["failed"] = serviceVerdict{at: now, known: true}
	s.verdicts["silent"] = serviceVerdict{at: now, known: true}

	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{
		// A manual re-test that never reached the service.
		"failed": {},
		// A manual re-test that answered but produced no verdict (429/5xx).
		"silent": {done: true, verdict: serviceVerdict{at: now}},
	}, s.Proxies(), now, true)
	failedDemoted := s.serviceUnusableLocked("failed", now)
	silentDemoted := s.serviceUnusableLocked("silent", now)
	failedConfirmed := s.serviceVerifiedLocked("failed", now)
	silentConfirmed := s.serviceVerifiedLocked("silent", now)
	s.mu.Unlock()

	if !failedDemoted || !silentDemoted {
		t.Fatalf("one manual re-test without a usable verdict must demote, got %+v and %+v",
			s.attempts["failed"], s.attempts["silent"])
	}
	if failedConfirmed || silentConfirmed {
		t.Fatal("a manual re-test without a usable verdict must drop the confirmation")
	}
}

func TestSmartBackgroundProbeKeepsFailLimit(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100))
	s.service = "google-gemini"
	now := time.Now()

	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{
		"a": {done: true, verdict: serviceVerdict{at: now}},
	}, s.Proxies(), now, false)
	demoted := s.serviceUnusableLocked("a", now)
	s.mu.Unlock()

	// A background run still needs the failure streak: one transient reset
	// must not cost the member its place.
	if demoted {
		t.Fatal("a single background probe without a verdict must not demote")
	}
}

func TestSmartForcedProbeRecoversOnAnswer(t *testing.T) {
	s := newTestSmartWithProxies(newFakeProxy("a", 100))
	s.service = "google-gemini"
	now := time.Now()

	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{"a": {}}, s.Proxies(), now, true)
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{
		"a": {done: true, verdict: serviceVerdict{at: now, known: true}},
	}, s.Proxies(), now, true)
	demoted := s.serviceUnusableLocked("a", now)
	confirmed := s.serviceVerifiedLocked("a", now)
	attempt := s.attempts["a"]
	s.mu.Unlock()

	if demoted {
		t.Fatal("an answered manual re-test must lift the demotion")
	}
	if !confirmed {
		t.Fatal("an answered manual re-test must confirm the member again")
	}
	if attempt.manual || attempt.fails != 0 || attempt.misses != 0 {
		t.Fatalf("an answered probe must clear every streak, got %+v", attempt)
	}
}

func TestSmartServicePinOutranksDemotion(t *testing.T) {
	pinned := newFakeProxy("Pinned", 100)
	confirmed := newFakeProxy("Confirmed", 400)
	s := newTestSmartWithProxies(pinned, confirmed)
	s.service = "google-gemini"
	now := time.Now()
	s.verdicts["Confirmed"] = serviceVerdict{at: now, known: true}
	s.ForceSet("Pinned")
	s.lastProbe = now

	if order := s.orderedCandidates(&C.Metadata{Host: "gemini.google.com"}, false); order[0].Name() != "Pinned" {
		t.Fatalf("a usable pin must stay first, got %v", names(order))
	}

	// A manual re-test without a usable verdict demotes the member, but the
	// lock is the user's choice: routing stays on it until the user unlocks.
	s.mu.Lock()
	s.applyProbeOutcomesLocked(map[string]serviceProbeOutcome{"Pinned": {}}, s.Proxies(), now, true)
	demoted := s.serviceUnusableLocked("Pinned", now)
	s.mu.Unlock()

	if !demoted {
		t.Fatal("the manual re-test must still record the demotion")
	}
	if order := s.orderedCandidates(&C.Metadata{Host: "gemini.google.com"}, false); order[0].Name() != "Pinned" {
		t.Fatalf("a locked member must keep the first pick, got %v", names(order))
	}
	if got := s.Now(); got != "Pinned" {
		t.Fatalf("the panel must name the locked member, got %s", got)
	}

	// Unlocking hands the group back to the ranking, where the recorded
	// demotion now counts against the former pin.
	s.ForceSet("")
	if order := s.orderedCandidates(&C.Metadata{Host: "gemini.google.com"}, false); order[0].Name() != "Confirmed" {
		t.Fatalf("after unlocking the confirmed member must lead, got %v", names(order))
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
		members, _ := s.selectServiceProbeMembersLocked(s.Proxies(), now)
		return names(members)
	}

	// Bootstrap: no verdict exists, so every alive candidate is probed at once.
	if got, want := selectNames(), []string{"Alive", "Slow"}; !slices.Equal(got, want) {
		t.Fatalf("bootstrap must probe every alive candidate, want %v got %v", want, got)
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

func TestSmartSelectServiceProbeMembersCandidateCap(t *testing.T) {
	var proxies []C.Proxy
	for i := 0; i < 40; i++ {
		proxies = append(proxies, newFakeProxy(fmt.Sprintf("P%02d", i), uint16(100+i*50)))
	}
	s := newTestSmartWithProxies(proxies...)
	s.service = "youtube"
	now := time.Now()
	candidates := make(map[string]struct{}, serviceProbeCandidates)
	for i := 0; i < serviceProbeCandidates; i++ {
		candidates[fmt.Sprintf("P%02d", i)] = struct{}{}
	}

	// A bootstrap run only touches the best-scored candidates, never the roster.
	s.mu.Lock()
	selected, offered := s.selectServiceProbeMembersLocked(s.Proxies(), now)
	s.mu.Unlock()
	if offered != serviceProbeCandidates {
		t.Fatalf("the candidate set must cap at %d, got %d", serviceProbeCandidates, offered)
	}
	if len(selected) != serviceProbeCandidates {
		t.Fatalf("a bootstrap run must probe the whole candidate set, got %v", names(selected))
	}
	for _, proxy := range selected {
		if _, ok := candidates[proxy.Name()]; !ok {
			t.Fatalf("a member outside the candidate set must not be probed: %v", names(selected))
		}
	}

	// Once every candidate is fresh the roster tail still waits untouched.
	s.mu.Lock()
	for _, proxy := range selected {
		s.verdicts[proxy.Name()] = serviceVerdict{at: now, known: true}
	}
	idle, _ := s.selectServiceProbeMembersLocked(s.Proxies(), now)
	s.mu.Unlock()
	if len(idle) != 0 {
		t.Fatalf("a fresh candidate set must not probe the roster tail, got %v", names(idle))
	}

	// After the refresh window the candidates return; the tail still never does.
	s.mu.Lock()
	stale, _ := s.selectServiceProbeMembersLocked(s.Proxies(), now.Add(serviceVerdictRefresh+time.Second))
	s.mu.Unlock()
	if len(stale) != serviceProbeCandidates {
		t.Fatalf("stale candidates must be re-probed, got %v", names(stale))
	}
	for _, proxy := range stale {
		if _, ok := candidates[proxy.Name()]; !ok {
			t.Fatalf("a member outside the candidate set must not be probed: %v", names(stale))
		}
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

func TestSmartServicePrefersVerifiedMember(t *testing.T) {
	unknown := newFakeProxy("Unknown", 100)           // fastest, never probed
	fastVerified := newFakeProxy("FastVerified", 400) // confirmed, slower than Unknown
	slowVerified := newFakeProxy("SlowVerified", 600)
	s := newTestSmartWithProxies(unknown, fastVerified, slowVerified)
	s.service = "google-gemini"
	now := time.Now()
	s.verdicts["FastVerified"] = serviceVerdict{at: now, known: true}
	s.verdicts["SlowVerified"] = serviceVerdict{at: now, known: true}
	s.lastProbe = now

	order := s.orderedCandidates(&C.Metadata{Host: "gemini.google.com"}, false)
	if got, want := names(order), []string{"FastVerified", "SlowVerified", "Unknown"}; !slices.Equal(got, want) {
		t.Fatalf("probe-confirmed members must come first, fastest of them leading: want %v got %v", want, got)
	}
}

func TestSmartServiceVerifiedLapsesOnFailedProbe(t *testing.T) {
	unknown := newFakeProxy("Unknown", 100)
	verified := newFakeProxy("Verified", 400)
	s := newTestSmartWithProxies(unknown, verified)
	s.service = "google-gemini"
	now := time.Now()
	s.verdicts["Verified"] = serviceVerdict{at: now, known: true}
	// One unanswered request since the verdict is enough to drop the
	// confirmation, even though it is not enough to demote the member.
	s.attempts["Verified"] = serviceProbeAttempt{at: now, fails: 1, misses: 1}
	s.lastProbe = now

	order := s.orderedCandidates(&C.Metadata{Host: "gemini.google.com"}, false)
	if got, want := names(order), []string{"Unknown", "Verified"}; !slices.Equal(got, want) {
		t.Fatalf("a failed probe must drop the confirmation, want %v got %v", want, got)
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

func TestSmartServiceGroupPinsAcrossDestinations(t *testing.T) {
	best := newFakeProxy("Best", 100)
	recent := newFakeProxy("Recent", 130) // inside the widened hit band
	s := newTestSmartWithProxies(best, recent)
	s.service = "youtube"
	now := time.Now()
	// One answered request anywhere in the group must fix the member for
	// every destination the service spans.
	s.rememberSite(&C.Metadata{Host: "www.youtube.com"}, "Recent", true, now.Add(-time.Minute))
	s.lastProbe = now

	for _, host := range []string{
		"www.youtube.com",
		"rr3---sn-abc.googlevideo.com",
		"i.ytimg.com",
		"api.youtube.com",
	} {
		order := s.orderedCandidates(&C.Metadata{Host: host}, false)
		if len(order) != 2 || order[0].Name() != "Recent" {
			t.Fatalf("host %s must ride the pinned member, got %v", host, names(order))
		}
	}
}

func TestSmartServiceGroupColdStartFixesBestMember(t *testing.T) {
	best := newFakeProxy("Best", 100)
	closeScore := newFakeProxy("Close", 110) // inside the band
	s := newTestSmartWithProxies(best, closeScore)
	s.service = "openai"
	s.lastProbe = time.Now()

	// No success remembered yet: every connection of the first burst must land
	// on the same member, so the pin forms on the first response instead of
	// spreading across the band.
	for i := 0; i < 32; i++ {
		order := s.orderedCandidates(&C.Metadata{Host: "chatgpt.com"}, false)
		if len(order) != 2 || order[0].Name() != "Best" {
			t.Fatalf("cold start must fix on the best member, got %v on call %d", names(order), i)
		}
	}
}

func TestSmartServiceGroupFailureMigratesThePin(t *testing.T) {
	best := newFakeProxy("Best", 100)
	recent := newFakeProxy("Recent", 130)
	s := newTestSmartWithProxies(best, recent)
	s.service = "youtube"
	now := time.Now()
	s.rememberSite(&C.Metadata{Host: "www.youtube.com"}, "Recent", true, now.Add(-2*time.Minute))
	// The pinned member failed; the fallback answered and re-pinned the group.
	s.rememberSite(&C.Metadata{Host: "i.ytimg.com"}, "Recent", false, now.Add(-time.Minute))
	s.rememberSite(&C.Metadata{Host: "rr3.example.googlevideo.com"}, "Best", true, now)
	s.lastProbe = now

	for _, host := range []string{"www.youtube.com", "i.ytimg.com", "api.youtube.com"} {
		if order := s.orderedCandidates(&C.Metadata{Host: host}, false); order[0].Name() != "Best" {
			t.Fatalf("host %s must ride the new pin, got %v", host, names(order))
		}
	}
}

func TestSmartNowReportsServiceGroupPin(t *testing.T) {
	best := newFakeProxy("Best", 100)
	recent := newFakeProxy("Recent", 130)
	s := newTestSmartWithProxies(best, recent)
	s.service = "openai"
	now := time.Now()

	// Cold start: the panel names the member the next request will fix on.
	if got := s.Now(); got != "Best" {
		t.Fatalf("cold start Now() = %q, want Best", got)
	}

	// The pin moved to a slower member without accumulated usage: the panel
	// follows the pin, not the score or the usage.
	s.rememberSite(&C.Metadata{Host: "chatgpt.com"}, "Recent", true, now)
	s.reportUsed("Best")
	s.reportUsed("Best")
	if got := s.Now(); got != "Recent" {
		t.Fatalf("pinned Now() = %q, want Recent", got)
	}

	// A manual pin still outranks the group pin.
	s.ForceSet("Best")
	if got := s.Now(); got != "Best" {
		t.Fatalf("manual pin Now() = %q, want Best", got)
	}
}

func TestSmartUnwrapFollowsServicePin(t *testing.T) {
	best := newFakeProxy("Best", 100)
	recent := newFakeProxy("Recent", 130)
	s := newTestSmartWithProxies(best, recent)
	s.service = "openai"
	now := time.Now()
	s.rememberSite(&C.Metadata{Host: "chatgpt.com"}, "Recent", true, now)

	if proxy := s.Unwrap(nil, false); proxy == nil || proxy.Name() != "Recent" {
		t.Fatalf("Unwrap must stand for the pinned member, got %v", proxy)
	}
}

func TestNewSmartPinOption(t *testing.T) {
	// The default and every unrecognized value keep the group pin; only an
	// explicit pin: site reverts a service group to per-site memory.
	cases := []struct {
		pin  string
		want bool
	}{
		{"", false},
		{"group", false},
		{" Group ", false},
		{"site", true},
		{"Site", true},
		{"sticky", false}, // unknown: degrade with a warning
	}
	for _, tc := range cases {
		s, err := NewSmart(GroupCommonOption{Name: "smart"}, SmartOption{Service: "gemini", Pin: tc.pin}, nil, nil)
		if err != nil {
			t.Fatalf("pin %q: unexpected error %v", tc.pin, err)
		}
		if s.pinSite != tc.want {
			t.Fatalf("pin %q: pinSite=%t, want %t", tc.pin, s.pinSite, tc.want)
		}
	}
}

func TestSmartServiceGroupSitePinPerSiteMemory(t *testing.T) {
	best := newFakeProxy("Best", 100)
	recent := newFakeProxy("Recent", 110) // inside the plain band
	s := newTestSmartWithProxies(best, recent)
	s.service = "openai"
	s.pinSite = true
	now := time.Now()
	s.rememberSite(&C.Metadata{Host: "chatgpt.com"}, "Recent", true, now.Add(-time.Minute))
	s.lastProbe = now

	// The record is per site: the site it served keeps its sticky pick...
	for i := 0; i < 16; i++ {
		if order := s.orderedCandidates(&C.Metadata{Host: "chatgpt.com"}, false); order[0].Name() != "Recent" {
			t.Fatalf("the served site must keep its sticky member, got %v", names(order))
		}
	}
	// ...while another destination of the same service rotates inside the
	// band instead of inheriting the pin.
	seen := make(map[string]bool, 2)
	for i := 0; i < 100; i++ {
		seen[s.orderedCandidates(&C.Metadata{Host: "cdn.example.org"}, false)[0].Name()] = true
	}
	if !seen["Best"] || !seen["Recent"] {
		t.Fatalf("an unrelated destination must rotate inside the band, saw %v", seen)
	}

	// Now() and Unwrap report usage and score, not the per-site record.
	s.reportUsed("Best")
	if got := s.Now(); got != "Best" {
		t.Fatalf("Now() = %q, want Best", got)
	}
	if proxy := s.Unwrap(nil, false); proxy == nil || proxy.Name() != "Best" {
		t.Fatalf("Unwrap must stand for the best alive member, got %v", proxy)
	}
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
	trusted := s.serviceUnusableLocked("a", now)
	s.verdicts["a"] = expired
	s.attempts["a"] = serviceProbeAttempt{at: now.Add(-time.Minute), misses: 2}
	trustedDuringBackoff := s.serviceUnusableLocked("a", now)
	s.attempts["a"] = serviceProbeAttempt{at: now.Add(-serviceProbeRetryMax - time.Minute), misses: 2}
	lapsed := s.serviceUnusableLocked("a", now)
	// An allowed verdict gets no such extension: an expired allowed member is
	// simply no longer boosted, and undecidable answers alone never demote it.
	// Repeated transport failures do, and they have their own test.
	s.verdicts["a"] = serviceVerdict{at: expired.at, known: true}
	allowed := s.serviceUnusableLocked("a", now)
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
		t.Fatal("an expired allowed verdict must not demote on undecidable answers alone")
	}
}
