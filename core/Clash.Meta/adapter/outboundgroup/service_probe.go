package outboundgroup

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	mihomoHttp "github.com/metacubex/mihomo/component/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

// The presets mirror lib/models/service_type.dart: the app shows one verdict in
// the media unlock panel and the core ranks members by the same rules, so a
// region edit must land on both sides.
const (
	serviceProbeTimeout = 5 * time.Second
	serviceProbeWorkers = 8
	// serviceProbeInterval throttles run starts, not member probes: runs are
	// incremental, so re-checking the member list once a minute is cheap.
	serviceProbeInterval = time.Minute
	// serviceVerdictRefresh is when a known verdict is re-probed. It sits below
	// the TTL with a margin wider than the run throttle plus a probe timeout,
	// so a member in active use never has its verdict lapse between runs.
	serviceVerdictRefresh = 15 * time.Minute
	// serviceVerdictTTL is how long a verdict is trusted for ranking when no
	// newer answer arrives (the group is idle or the probes keep failing).
	serviceVerdictTTL = 20 * time.Minute
	// serviceProbeRetry backs off a member whose last attempt produced no
	// verdict, so an unreachable member is not retried on every connection.
	serviceProbeRetry = 5 * time.Minute
	// serviceProbeBatch caps one run; deeper members wait for later runs, so
	// the probe budget follows the ranking instead of the roster.
	serviceProbeBatch = 12

	serviceProbeMaxBody = 256 << 10
)

type servicePreset struct {
	url string
	// trace reads Cloudflare's /cdn-cgi/trace key=value body; otherwise the body
	// is a service page that only reveals the region through its payload.
	trace bool
	// regionPatterns extract the region from a page body; the first match wins.
	regionPatterns []*regexp.Regexp
	// blockedPaths mark a redirect target as unusable even when it answers 200.
	blockedPaths []string
	// unavailablePhrases mark a 200 page as unusable; matched against the lower
	// cased body.
	unavailablePhrases []string
	blocked            map[string]struct{}
}

var servicePresets = map[string]servicePreset{
	"openai": {
		url:   "https://chatgpt.com/cdn-cgi/trace",
		trace: true,
		blocked: serviceRegionSet(
			"CN", "HK", "MO", "RU", "IR", "KP", "SY", "CU", "VE", "BY",
			"AF", "SS", "YE", "ZW", "MM", "SD", "SO", "CF",
		),
	},
	"google-gemini": {
		url:            "https://gemini.google.com/",
		regionPatterns: geminiRegionPatterns,
		blockedPaths:   []string{"sorry.google.com"},
		unavailablePhrases: []string{
			"not supported in your country",
			"isn't supported in your country",
			"not available in your country",
			"unavailable in your country",
			"not currently supported",
			"isn't currently supported",
			"不支持您所在的国家",
			"不支持你所在的国家",
			"无法在您所在的国家",
			"無法在您所在的國家",
			"ご利用いただけません",
		},
		blocked: serviceRegionSet(
			"CN", "CHN", "RU", "RUS", "BY", "BLR", "IR", "IRN", "KP", "PRK",
			"SY", "SYR", "CU", "CUB", "VE", "VEN", "MM", "MMR", "SD", "SDN",
			"AF", "AFG", "SS", "SSD", "YE", "YEM", "ZW", "ZWE",
		),
	},
	// YouTube is not refused by region: a member only fails when the request
	// itself lands on an unavailable page. The region stays for logging and for
	// the app's unlock panel, so the preset keeps no blocked region.
	"youtube": {
		url:            "https://www.youtube.com/premium",
		regionPatterns: youtubeRegionPatterns,
		blockedPaths:   []string{"sorry.google.com", "www.google.cn"},
		unavailablePhrases: []string{
			"youtube isn't available in your country",
			"youtube is not available in your country",
			"youtube is unavailable in your country",
			"www.google.cn",
		},
		blocked: serviceRegionSet(),
	},
}

var serviceAliases = map[string]string{
	"":               "",
	"openai":         "openai",
	"chatgpt":        "openai",
	"google-gemini":  "google-gemini",
	"gemini":         "google-gemini",
	"youtube":        "youtube",
	"google-youtube": "youtube",
}

func serviceRegionSet(regions ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		set[region] = struct{}{}
	}
	return set
}

// normalizeServiceName maps the configured value onto a preset key and reports
// a typo instead of silently ranking every member the same.
func normalizeServiceName(name string) (string, error) {
	key, ok := serviceAliases[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return "", fmt.Errorf("unknown service %q", name)
	}
	return key, nil
}

// serviceVerdict is the last probe result of one member. An undecidable answer
// leaves the member's ranking untouched: the html page preset demotes on a 4xx
// page but treats 429 and 5xx as undecidable, while the trace preset treats any
// non-2xx/3xx answer or a body without an ip as undecidable.
type serviceVerdict struct {
	at      time.Time
	known   bool
	blocked bool
	region  string
}

// serviceProbeOutcome is one member's result in a probe run: done is false
// when the request itself failed, in which case only the attempt is recorded.
type serviceProbeOutcome struct {
	verdict serviceVerdict
	done    bool
}

var geminiRegionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`,2,1,200,"([A-Z]{3})"`),
	regexp.MustCompile(`\[1,null,null,\d+,\d+,"([A-Z]{3})"`),
}

var youtubeRegionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"`),
	regexp.MustCompile(`"countryCode"\s*:\s*"([A-Z]{2})"`),
	regexp.MustCompile(`"REQUEST_DOMAIN"\s*:\s*"([a-zA-Z]{2})"`),
}

func parseTraceBody(body string) (ip, loc, colo string, warp bool) {
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "ip":
			ip = strings.TrimSpace(value)
		case "loc":
			loc = strings.TrimSpace(value)
		case "colo":
			colo = strings.TrimSpace(value)
		case "warp":
			warp = strings.TrimSpace(value) != "off"
		}
	}
	return ip, loc, colo, warp
}

// evaluateServiceResponse turns one probe response into a verdict. It stays
// pure so the region policy can be tested without a network or a proxy.
func evaluateServiceResponse(preset servicePreset, status int, finalURL, body string) serviceVerdict {
	verdict := serviceVerdict{at: time.Now()}
	if preset.trace {
		ip, loc, _, _ := parseTraceBody(body)
		verdict.region = strings.ToUpper(loc)
		if ip == "" || status < 200 || status >= 400 {
			return verdict
		}
		verdict.known = true
		_, verdict.blocked = preset.blocked[verdict.region]
		return verdict
	}

	// A rate limit or an upstream error is not an answer about the member's
	// region; keep the previous ranking instead of demoting it for the TTL.
	if status == 429 || status >= 500 {
		return verdict
	}

	for _, pattern := range preset.regionPatterns {
		if match := pattern.FindStringSubmatch(body); match != nil {
			verdict.region = strings.ToUpper(match[1])
			break
		}
	}
	verdict.known = true
	if status != 200 {
		verdict.blocked = true
		return verdict
	}
	lowerURL := strings.ToLower(finalURL)
	for _, path := range preset.blockedPaths {
		if path != "" && strings.Contains(lowerURL, strings.ToLower(path)) {
			verdict.blocked = true
			return verdict
		}
	}
	if _, blockedRegion := preset.blocked[strings.ToUpper(verdict.region)]; blockedRegion {
		verdict.blocked = true
		return verdict
	}
	lowerBody := strings.ToLower(body)
	for _, phrase := range preset.unavailablePhrases {
		if strings.Contains(lowerBody, phrase) {
			verdict.blocked = true
			return verdict
		}
	}
	return verdict
}

// probeServiceVerdict fetches one service through one member. The request goes
// through the inner tunnel so the member is used as-is, like proxy-provider
// downloads do.
func probeServiceVerdict(ctx context.Context, proxyName, service string) (serviceVerdict, error) {
	preset, ok := servicePresets[service]
	if !ok {
		return serviceVerdict{}, fmt.Errorf("unknown service %q", service)
	}
	resp, err := mihomoHttp.HttpRequest(
		ctx,
		preset.url,
		http.MethodGet,
		map[string][]string{
			"Accept-Language": {"en-US,en;q=0.9"},
			"User-Agent": {
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
					"(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
			},
		},
		nil,
		mihomoHttp.WithSpecialProxy(proxyName),
	)
	if err != nil {
		return serviceVerdict{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, serviceProbeMaxBody))
	if err != nil {
		return serviceVerdict{}, err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return evaluateServiceResponse(preset, resp.StatusCode, finalURL, string(body)), nil
}

func (s *Smart) probeServiceMembers(proxies []C.Proxy, service string) map[string]serviceProbeOutcome {
	sem := make(chan struct{}, serviceProbeWorkers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	outcomes := make(map[string]serviceProbeOutcome, len(proxies))
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}
		proxy := proxy
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), serviceProbeTimeout)
			defer cancel()
			verdict, err := probeServiceVerdict(ctx, proxy.Name(), service)
			mu.Lock()
			if err != nil {
				// A failed request says nothing about the member's region; it only
				// counts as an attempt so the retry backoff can pace it.
				outcomes[proxy.Name()] = serviceProbeOutcome{}
				log.Debugln("[Smart] service %s via %s: probe failed: %v", service, proxy.Name(), err)
			} else {
				outcomes[proxy.Name()] = serviceProbeOutcome{verdict: verdict, done: true}
				log.Debugln("[Smart] service %s via %s: region=%q known=%t blocked=%t",
					service, proxy.Name(), verdict.region, verdict.known, verdict.blocked)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return outcomes
}

// selectServiceProbeMembersLocked returns the members the next run should
// probe: alive members without a fresh verdict, best score first, capped at
// serviceProbeBatch. With no fresh verdict at all the cap is lifted, so a group
// bootstrapping or waking from idle re-learns its whole roster in one run.
// Callers must hold s.mu.
func (s *Smart) selectServiceProbeMembersLocked(proxies []C.Proxy, now time.Time) []C.Proxy {
	fresh := 0
	type pendingMember struct {
		proxy C.Proxy
		score float64
	}
	pending := make([]pendingMember, 0, len(proxies))
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}
		name := proxy.Name()
		if verdict, ok := s.verdicts[name]; ok && verdict.known && now.Sub(verdict.at) < serviceVerdictRefresh {
			fresh++
			continue
		}
		if attempt, ok := s.attempts[name]; ok && now.Sub(attempt) < serviceProbeRetry {
			continue
		}
		// A member whose URL test failed cannot be picked anyway; its verdict
		// matters again once it answers, and this scan runs every minute.
		if !proxy.AliveForTestUrl(s.testUrl) {
			continue
		}
		pending = append(pending, pendingMember{proxy: proxy, score: s.scoreOf(proxy, s.states[name], now)})
	}
	if len(pending) == 0 {
		return nil
	}
	if fresh > 0 {
		sort.SliceStable(pending, func(i, j int) bool { return pending[i].score < pending[j].score })
		if len(pending) > serviceProbeBatch {
			pending = pending[:serviceProbeBatch]
		}
	}
	members := make([]C.Proxy, 0, len(pending))
	for _, item := range pending {
		members = append(members, item.proxy)
	}
	return members
}

// maybeProbeService probes the members that currently lack a fresh verdict, on
// the first connection after the throttle window and on dial-failure health
// checks. Idle groups dial nothing: without traffic or failures there is no
// trigger, and a run only spends requests on members whose verdict is missing
// or older than serviceVerdictRefresh.
func (s *Smart) maybeProbeService(proxies []C.Proxy) {
	if s.service == "" || len(proxies) == 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	if s.probing || (!s.lastProbe.IsZero() && now.Sub(s.lastProbe) < serviceProbeInterval) {
		s.mu.Unlock()
		return
	}
	selected := s.selectServiceProbeMembersLocked(proxies, now)
	if len(selected) == 0 {
		s.mu.Unlock()
		return
	}
	s.probing = true
	s.lastProbe = now
	s.mu.Unlock()

	go func() {
		log.Debugln("[Smart] %s: probing %d/%d members for service %s",
			s.Name(), len(selected), len(proxies), s.service)
		outcomes := s.probeServiceMembers(selected, s.service)
		s.mu.Lock()
		s.probing = false
		s.applyProbeOutcomesLocked(outcomes, proxies, time.Now())
		s.invalidateRankCacheLocked()
		s.mu.Unlock()
	}()
}

// applyProbeOutcomesLocked records one run's results: a known verdict replaces
// the member's previous one, while an undecidable answer or a failed request
// only marks the attempt, so the old verdict keeps its weight until its TTL and
// the member is not retried immediately. Verdicts of members that left the
// group are dropped instead of lingering forever. Callers must hold s.mu.
func (s *Smart) applyProbeOutcomesLocked(outcomes map[string]serviceProbeOutcome, members []C.Proxy, now time.Time) {
	current := make(map[string]struct{}, len(members))
	for _, proxy := range members {
		if proxy != nil {
			current[proxy.Name()] = struct{}{}
		}
	}
	for name, outcome := range outcomes {
		if s.attempts == nil {
			s.attempts = make(map[string]time.Time, len(outcomes))
		}
		s.attempts[name] = now
		if outcome.done && outcome.verdict.known {
			if s.verdicts == nil {
				s.verdicts = make(map[string]serviceVerdict, len(outcomes))
			}
			s.verdicts[name] = outcome.verdict
		}
	}
	for name := range s.verdicts {
		if _, ok := current[name]; !ok {
			delete(s.verdicts, name)
		}
	}
	for name := range s.attempts {
		if _, ok := current[name]; !ok {
			delete(s.attempts, name)
		}
	}
}

// serviceBlockedLocked reports whether the member failed its last service
// probe. Callers must hold s.mu.
func (s *Smart) serviceBlockedLocked(name string, now time.Time) bool {
	if s.service == "" {
		return false
	}
	verdict, ok := s.verdicts[name]
	if !ok || !verdict.known {
		return false
	}
	if now.Sub(verdict.at) > serviceVerdictTTL {
		return false
	}
	return verdict.blocked
}
