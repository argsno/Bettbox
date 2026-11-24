package outboundgroup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

// The presets mirror lib/models/service_type.dart: the app shows one verdict in
// the media unlock panel and the core ranks members by the same rules, so a
// region edit must land on both sides.
const (
	// serviceProbeTimeout covers the whole request including the body read. The
	// Gemini preset reads a full page to reach its region payload, so a tight
	// deadline would fail members that are merely slow instead of unreachable.
	serviceProbeTimeout = 15 * time.Second
	serviceProbeWorkers = 8
	// serviceProbeGlobalWorkers caps concurrent service probes across all Smart
	// groups so bulk refreshes cannot overwhelm the network or trigger 429s.
	serviceProbeGlobalWorkers = 16
	// serviceProbeShareTTL reuses an identical (proxy, service) probe answer
	// across different Smart groups within a short window.
	serviceProbeShareTTL = 30 * time.Second
	// serviceProbeInterval throttles run starts, not member probes: runs are
	// incremental, so re-checking the member list once a minute is cheap.
	serviceProbeInterval = time.Minute
	// serviceVerdictRefresh is when a known verdict is re-probed. It sits below
	// the TTL with a margin wider than the run throttle plus a probe timeout,
	// so a member in active use never has its verdict lapse between runs.
	serviceVerdictRefresh = 30 * time.Minute
	// serviceVerdictTTL is how long a verdict is trusted for ranking when no
	// newer answer arrives (the group is idle or the probes keep failing).
	serviceVerdictTTL = 45 * time.Minute
	// serviceProbeRetry paces the retry of a member whose last attempt produced
	// no decidable answer; consecutive misses double it up to serviceProbeRetryMax,
	// so an unreachable member is relearned quickly at first and rarely later.
	serviceProbeRetry    = 5 * time.Minute
	serviceProbeRetryMax = 40 * time.Minute
	// serviceProbeFailLimit is how many consecutive requests without any answer
	// demote a member. A decidable verdict is not the only evidence: an egress
	// that keeps resetting or black-holing the service is unusable even though
	// no probe ever produced a verdict about it.
	serviceProbeFailLimit = 3
	// serviceProbeBatch caps one run. It matches the candidate cap today, so a
	// bootstrap finishes in one run instead of two.
	serviceProbeBatch = 12
	// serviceProbeCandidates is the target number of healthy (usable or pending)
	// top-ranked members the group keeps probed. Blocked or backed-off members
	// do not consume this quota so a blocked low-latency region (e.g. HK for
	// OpenAI) cannot starve usable regions further down the list.
	serviceProbeCandidates = 12
	// serviceProbeMaxScan bounds how far down the ranking a single run scans
	// when many top members are blocked.
	serviceProbeMaxScan = 64

	serviceProbeMaxBody = 256 << 10
	// serviceProbeGeminiMaxBody covers the region payload of the Gemini page,
	// which sits past the first megabyte; the default cap would truncate it and
	// leave every member with an unreadable region.
	serviceProbeGeminiMaxBody = 2 << 20
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
	// maxBody caps the response read; zero means serviceProbeMaxBody.
	maxBody int64
	// skipBody judges the member from the status and the final URL only and
	// leaves the response body unread. It pauses a body check whose page is too
	// heavy for what the check adds to the routing decision.
	skipBody bool
	blocked  map[string]struct{}
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
		maxBody:        serviceProbeGeminiMaxBody,
		regionPatterns: geminiRegionPatterns,
		blockedPaths:   []string{"sorry.google.com", "unavailable"},
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
	//
	// The body judgment is paused: /premium is a ~1 MB page and the phrases it
	// adds almost never change the routing decision, so the probe only reads the
	// status and the final URL (skipBody). The rules stay here for the restart;
	// dropping skipBody is enough, because the incremental read already stops at
	// the first region marker (~62 KB for this page).
	"youtube": {
		url:            "https://www.youtube.com/premium",
		skipBody:       true,
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

// serviceBodyLimit is the response read cap for one preset.
func serviceBodyLimit(preset servicePreset) int64 {
	if preset.maxBody > 0 {
		return preset.maxBody
	}
	return serviceProbeMaxBody
}

const (
	// serviceBodyChunk is the read size of the incremental body scan. Chunking
	// lets the scan stop at the region marker instead of paying for the rest of
	// a ~1 MB page.
	serviceBodyChunk = 32 << 10
	// serviceBodyOverlap keeps a region pattern or phrase that straddles two
	// chunks intact.
	serviceBodyOverlap = 256
)

// readServiceBody reads the response up to the preset's cap and stops as soon
// as a region pattern matches. Kept for tests and trace/small-body callers.
func readServiceBody(preset servicePreset, body io.Reader) (string, error) {
	reader := io.LimitReader(body, serviceBodyLimit(preset))
	buf := make([]byte, 0, serviceBodyChunk)
	chunk := make([]byte, serviceBodyChunk)
	scanned := 0
	for {
		n, err := reader.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if len(preset.regionPatterns) > 0 {
				start := scanned - serviceBodyOverlap
				if start < 0 {
					start = 0
				}
				end := len(buf)
				scanned = end
				for _, pattern := range preset.regionPatterns {
					if pattern.Match(buf[start:end]) {
						return string(buf), nil
					}
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return string(buf), nil
}

// scanServiceBody streams the response body using a fixed sliding window
// (chunk + overlap) so large HTML pages like Gemini do not retain multi-MB
// buffers or allocate a full lowercased copy.
func scanServiceBody(preset servicePreset, body io.Reader) (region string, unavailable bool, err error) {
	reader := io.LimitReader(body, serviceBodyLimit(preset))
	chunk := make([]byte, serviceBodyChunk)
	window := make([]byte, 0, serviceBodyChunk+serviceBodyOverlap)
	lowerPhrases := make([][]byte, 0, len(preset.unavailablePhrases))
	for _, phrase := range preset.unavailablePhrases {
		if phrase != "" {
			lowerPhrases = append(lowerPhrases, []byte(strings.ToLower(phrase)))
		}
	}

	for {
		n, rerr := reader.Read(chunk)
		if n > 0 {
			window = append(window, chunk[:n]...)
			if len(lowerPhrases) > 0 {
				lowerWin := bytes.ToLower(window)
				for _, phrase := range lowerPhrases {
					if bytes.Contains(lowerWin, phrase) {
						return region, true, nil
					}
				}
			}
			if region == "" && len(preset.regionPatterns) > 0 {
				for _, pattern := range preset.regionPatterns {
					if match := pattern.FindSubmatch(window); match != nil {
						region = strings.ToUpper(string(match[1]))
						// Stop as soon as the region is extracted, matching readServiceBody.
						return region, false, nil
					}
				}
			}
			if len(window) > serviceBodyOverlap {
				copy(window[:serviceBodyOverlap], window[len(window)-serviceBodyOverlap:])
				window = window[:serviceBodyOverlap]
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", false, rerr
		}
	}
	return region, false, nil
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

type persistedServiceVerdict struct {
	At      int64  `json:"at"`
	Known   bool   `json:"known"`
	Blocked bool   `json:"blocked"`
	Region  string `json:"region,omitempty"`
}

func smartVerdictCacheKey(service, proxyName string) string {
	return service + "\x00" + proxyName
}

// serviceProbeOutcome is one member's result in a probe run: done is false
// when the request itself failed, in which case only the attempt is recorded
// and the member's failure streak grows.
type serviceProbeOutcome struct {
	verdict serviceVerdict
	done    bool
}

// serviceProbeAttempt records a member's last probe try, decidable or not.
// misses counts the consecutive tries that produced no decidable answer and
// drives the exponential backoff; a decidable answer resets it. fails counts
// the consecutive tries whose request never completed at all: a response, even
// an undecidable one, proves the member can reach the service. manual marks a
// demotion a forced re-test produced, where a single try without a usable
// verdict is already the answer the user asked for.
type serviceProbeAttempt struct {
	at     time.Time
	misses int
	fails  int
	manual bool
}

// demoted reports whether the attempt alone keeps the member out of the
// preferred pick, before the lapse window is applied.
func (a serviceProbeAttempt) demoted() bool {
	return a.manual || a.fails >= serviceProbeFailLimit
}

// backoff doubles serviceProbeRetry per consecutive miss, capped at
// serviceProbeRetryMax.
func (a serviceProbeAttempt) backoff() time.Duration {
	if a.misses <= 1 {
		return serviceProbeRetry
	}
	backoff := serviceProbeRetry
	for i := 1; i < a.misses; i++ {
		backoff *= 2
		if backoff >= serviceProbeRetryMax {
			return serviceProbeRetryMax
		}
	}
	return backoff
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
	return evaluateServiceHTMLMeta(preset, status, finalURL, verdict.region, containsUnavailablePhrase(preset, body))
}

func containsUnavailablePhrase(preset servicePreset, body string) bool {
	if len(preset.unavailablePhrases) == 0 || body == "" {
		return false
	}
	lowerBody := strings.ToLower(body)
	for _, phrase := range preset.unavailablePhrases {
		if strings.Contains(lowerBody, phrase) {
			return true
		}
	}
	return false
}

func evaluateServiceHTMLMeta(preset servicePreset, status int, finalURL, region string, unavailable bool) serviceVerdict {
	verdict := serviceVerdict{
		at:     time.Now(),
		region: strings.ToUpper(region),
	}
	if status == 429 || status >= 500 {
		return verdict
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
	if _, blockedRegion := preset.blocked[verdict.region]; blockedRegion {
		verdict.blocked = true
		return verdict
	}
	if unavailable {
		verdict.blocked = true
		return verdict
	}
	return verdict
}

type sharedServiceProbeKey struct {
	proxy   C.Proxy
	service string
}

type sharedServiceProbeFlight struct {
	done    chan struct{}
	verdict serviceVerdict
	err     error
}

type sharedServiceProbeEntry struct {
	at      time.Time
	verdict serviceVerdict
}

var (
	sharedServiceProbeSlots = make(chan struct{}, serviceProbeGlobalWorkers)
	sharedServiceProbeMu    sync.Mutex
	sharedServiceProbes     = map[sharedServiceProbeKey]*sharedServiceProbeFlight{}
	sharedServiceCache      = map[sharedServiceProbeKey]sharedServiceProbeEntry{}
)

// probeServiceViaProxy executes a direct HTTP probe through the target proxy's
// DialContext without passing through inner.HandleTcp, avoiding tunnel retries,
// statistic tracker pollution, and unclosed keep-alive pools.
func probeServiceViaProxy(ctx context.Context, proxy C.Proxy, service string) (serviceVerdict, error) {
	preset, ok := servicePresets[service]
	if !ok {
		return serviceVerdict{}, fmt.Errorf("unknown service %q", service)
	}
	if proxy == nil {
		return serviceVerdict{}, fmt.Errorf("nil proxy")
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return serviceVerdict{}, err
	}

	transport := &http.Transport{
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsConfig,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			var metadata C.Metadata
			if err := metadata.SetRemoteAddress(address); err != nil {
				return nil, err
			}
			return proxy.DialContext(dialCtx, &metadata)
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, preset.url, nil)
	if err != nil {
		return serviceVerdict{}, err
	}
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")

	client := http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return serviceVerdict{}, err
	}
	defer resp.Body.Close()

	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	if preset.skipBody {
		return evaluateServiceHTMLMeta(preset, resp.StatusCode, finalURL, "", false), nil
	}
	if preset.trace {
		body, err := readServiceBody(preset, resp.Body)
		if err != nil {
			return serviceVerdict{}, err
		}
		return evaluateServiceResponse(preset, resp.StatusCode, finalURL, body), nil
	}
	if resp.StatusCode == 429 || resp.StatusCode >= 500 || resp.StatusCode != 200 {
		return evaluateServiceHTMLMeta(preset, resp.StatusCode, finalURL, "", false), nil
	}
	// Check blockedPaths before reading the body to abort redirects early.
	lowerURL := strings.ToLower(finalURL)
	for _, path := range preset.blockedPaths {
		if path != "" && strings.Contains(lowerURL, strings.ToLower(path)) {
			return evaluateServiceHTMLMeta(preset, resp.StatusCode, finalURL, "", false), nil
		}
	}
	region, unavailable, err := scanServiceBody(preset, resp.Body)
	if err != nil {
		return serviceVerdict{}, err
	}
	return evaluateServiceHTMLMeta(preset, resp.StatusCode, finalURL, region, unavailable), nil
}

// probeServiceShared deduplicates concurrent probes for the same (proxy, service)
// across Smart groups and enforces the process-wide concurrency cap.
func probeServiceShared(ctx context.Context, proxy C.Proxy, service string, forced bool) (serviceVerdict, error) {
	key := sharedServiceProbeKey{proxy: proxy, service: service}
	now := time.Now()

	sharedServiceProbeMu.Lock()
	if !forced {
		if cached, ok := sharedServiceCache[key]; ok && now.Sub(cached.at) < serviceProbeShareTTL {
			sharedServiceProbeMu.Unlock()
			return cached.verdict, nil
		}
	}
	if flight, ok := sharedServiceProbes[key]; ok {
		sharedServiceProbeMu.Unlock()
		select {
		case <-flight.done:
			return flight.verdict, flight.err
		case <-ctx.Done():
			return serviceVerdict{}, ctx.Err()
		}
	}
	flight := &sharedServiceProbeFlight{done: make(chan struct{})}
	sharedServiceProbes[key] = flight
	sharedServiceProbeMu.Unlock()

	defer func() {
		sharedServiceProbeMu.Lock()
		delete(sharedServiceProbes, key)
		if flight.err == nil && flight.verdict.known {
			if len(sharedServiceCache) > 1024 {
				cutoff := time.Now().Add(-serviceProbeShareTTL)
				for k, v := range sharedServiceCache {
					if v.at.Before(cutoff) {
						delete(sharedServiceCache, k)
					}
				}
			}
			sharedServiceCache[key] = sharedServiceProbeEntry{at: time.Now(), verdict: flight.verdict}
		}
		sharedServiceProbeMu.Unlock()
		close(flight.done)
	}()

	select {
	case sharedServiceProbeSlots <- struct{}{}:
	case <-ctx.Done():
		flight.err = ctx.Err()
		return serviceVerdict{}, ctx.Err()
	}
	defer func() { <-sharedServiceProbeSlots }()

	flight.verdict, flight.err = probeServiceViaProxy(ctx, proxy, service)
	return flight.verdict, flight.err
}

// probeServiceFunc is overridable in tests so probe orchestration can be tested
// deterministically without live network access.
var probeServiceFunc = probeServiceShared

func (s *Smart) probeServiceMembers(parentCtx context.Context, proxies []C.Proxy, service string, forced bool) map[string]serviceProbeOutcome {
	sem := make(chan struct{}, serviceProbeWorkers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	outcomes := make(map[string]serviceProbeOutcome, len(proxies))
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}
		if parentCtx.Err() != nil {
			break
		}
		proxy := proxy
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-parentCtx.Done():
			wg.Done()
			break
		}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(parentCtx, serviceProbeTimeout)
			defer cancel()
			verdict, err := probeServiceFunc(ctx, proxy, service, forced)
			if parentCtx.Err() != nil {
				return
			}
			mu.Lock()
			if err != nil {
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
// probe, and the number of usable/pending candidate slots evaluated.
//
// Known-blocked or backed-off members do not consume the candidate quota, so
// low-latency blocked regions (for example HK nodes on OpenAI) cannot prevent
// the group from discovering usable nodes further down the latency ranking.
// Callers must hold s.mu (read or write lock).
func (s *Smart) selectServiceProbeMembersLocked(proxies []C.Proxy, now time.Time) ([]C.Proxy, int) {
	snaps := snapshotProxyHealth(proxies, s.testUrl)
	return s.selectServiceProbeMembersFromSnapLocked(proxies, snaps, now)
}

func (s *Smart) selectServiceProbeMembersFromSnapLocked(proxies []C.Proxy, snaps []proxyHealthSnap, now time.Time) ([]C.Proxy, int) {
	type candidate struct {
		proxy C.Proxy
		score float64
	}
	ranking := make([]candidate, 0, len(proxies))
	for i, proxy := range proxies {
		if proxy == nil || !snaps[i].alive {
			continue
		}
		ranking = append(ranking, candidate{
			proxy: proxy,
			score: s.scoreOfSnapLocked(proxy.Name(), snaps[i].delay, s.states[proxy.Name()], now),
		})
	}
	sort.SliceStable(ranking, func(i, j int) bool { return ranking[i].score < ranking[j].score })

	pending := make([]C.Proxy, 0, serviceProbeBatch)
	var staleBlocked []C.Proxy
	offered := 0
	scanned := 0

	for _, item := range ranking {
		if offered >= serviceProbeCandidates || scanned >= serviceProbeMaxScan {
			break
		}
		scanned++
		name := item.proxy.Name()
		verdict, hasVerdict := s.verdicts[name]
		attempt, hasAttempt := s.attempts[name]
		inBackoff := hasAttempt && now.Sub(attempt.at) < attempt.backoff()

		if hasVerdict && verdict.known && verdict.blocked {
			if now.Sub(verdict.at) < serviceVerdictRefresh || inBackoff {
				// Blocked and still fresh/backing off: skip without consuming usable quota.
				continue
			}
			// Stale blocked member: remember for low-priority re-check after usable pool fills.
			staleBlocked = append(staleBlocked, item.proxy)
			continue
		}

		if hasAttempt && attempt.demoted() && inBackoff {
			// Repeatedly failing / manually demoted member in backoff does not consume quota.
			continue
		}

		offered++
		if hasVerdict && verdict.known && now.Sub(verdict.at) < serviceVerdictRefresh {
			continue
		}
		if inBackoff {
			continue
		}
		if len(pending) < serviceProbeBatch {
			pending = append(pending, item.proxy)
		}
	}

	// If usable candidates are already fresh and there is room in the batch, refresh
	// stale blocked members so nodes that regained unlock can recover.
	for _, proxy := range staleBlocked {
		if len(pending) >= serviceProbeBatch {
			break
		}
		pending = append(pending, proxy)
	}

	return pending, offered
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
	s.mu.RLock()
	if s.probing || (!s.lastProbe.IsZero() && now.Sub(s.lastProbe) < serviceProbeInterval) {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	snaps := snapshotProxyHealth(proxies, s.testUrl)

	s.mu.Lock()
	if s.probing || (!s.lastProbe.IsZero() && now.Sub(s.lastProbe) < serviceProbeInterval) {
		s.mu.Unlock()
		return
	}
	selected, candidates := s.selectServiceProbeMembersFromSnapLocked(proxies, snaps, now)
	if len(selected) == 0 {
		s.mu.Unlock()
		return
	}
	log.Debugln("[Smart] %s: probing %d of %d candidates (%d members) for service %s",
		s.Name(), len(selected), candidates, len(proxies), s.service)
	s.startServiceProbeLocked(selected, proxies, false)
	s.mu.Unlock()
}

// ForceServiceProbe re-probes the named members now, ignoring the verdict
// freshness and the retry backoff. The app calls it when the user manually
// tests a node, so a demoted member can be recovered without waiting for its
// backoff window.
func (s *Smart) ForceServiceProbe(names []string) {
	if s.service == "" || len(names) == 0 {
		return
	}
	proxies := s.GetProxies(false)
	// Read the current pick and proxy health before taking s.mu.
	current := s.Now()
	snaps := snapshotProxyHealth(proxies, s.testUrl)
	now := time.Now()
	s.mu.Lock()
	if s.probing {
		if s.forcePending == nil {
			s.forcePending = make(map[string]struct{}, len(names))
		}
		for _, name := range names {
			s.forcePending[name] = struct{}{}
		}
		s.forcePendingCurrent = current
		s.mu.Unlock()
		return
	}
	targets := s.forceProbeTargetsFromSnapLocked(proxies, snaps, names, current, now)
	if len(targets) == 0 {
		s.mu.Unlock()
		return
	}
	log.Debugln("[Smart] %s: force probing %d member(s) for service %s", s.Name(), len(targets), s.service)
	s.startServiceProbeLocked(targets, proxies, true)
	s.mu.Unlock()
}

// forceProbeTargetsLocked picks the members a manual re-test should probe: the
// current member when it was tested, plus the other tested members that are
// currently unusable and alive. Callers must hold s.mu.
func (s *Smart) forceProbeTargetsLocked(proxies []C.Proxy, names []string, current string, now time.Time) []C.Proxy {
	snaps := snapshotProxyHealth(proxies, s.testUrl)
	return s.forceProbeTargetsFromSnapLocked(proxies, snaps, names, current, now)
}

func (s *Smart) forceProbeTargetsFromSnapLocked(proxies []C.Proxy, snaps []proxyHealthSnap, names []string, current string, now time.Time) []C.Proxy {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	forceCurrent := false
	if current != "" {
		_, forceCurrent = wanted[current]
	}
	type candidate struct {
		proxy C.Proxy
		score float64
	}
	var currentTarget C.Proxy
	others := make([]candidate, 0, len(names))
	for i, proxy := range proxies {
		if proxy == nil || !snaps[i].alive {
			continue
		}
		name := proxy.Name()
		if _, ok := wanted[name]; !ok {
			continue
		}
		if forceCurrent && name == current {
			currentTarget = proxy
			continue
		}
		if !s.serviceUnusableLocked(name, now) {
			continue
		}
		others = append(others, candidate{
			proxy: proxy,
			score: s.scoreOfSnapLocked(name, snaps[i].delay, s.states[name], now),
		})
	}
	sort.SliceStable(others, func(i, j int) bool { return others[i].score < others[j].score })
	targets := make([]C.Proxy, 0, serviceProbeBatch)
	if currentTarget != nil {
		targets = append(targets, currentTarget)
	}
	for _, item := range others {
		if len(targets) >= serviceProbeBatch {
			break
		}
		targets = append(targets, item.proxy)
	}
	return targets
}

// startServiceProbeLocked starts one probe run over targets. members is the
// full member list, so outcomes for members that left the group are pruned.
// forced marks a run a manual re-test triggered, where a member without a
// usable verdict is demoted on that one try. Callers must hold s.mu.
func (s *Smart) startServiceProbeLocked(targets, members []C.Proxy, forced bool) {
	s.probing = true
	s.lastProbe = time.Now()
	probeCtx := s.probeContext()
	service := s.service
	go func() {
		outcomes := s.probeServiceMembers(probeCtx, targets, service, forced)
		if probeCtx.Err() != nil {
			s.mu.Lock()
			s.probing = false
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		s.probing = false
		changed := s.applyProbeOutcomesLocked(outcomes, members, time.Now(), forced)
		s.invalidateRankCacheLocked()
		s.startPendingProbeLocked(members, targets)
		s.mu.Unlock()

		persistServiceVerdicts(service, outcomes)
		if changed || len(outcomes) > 0 {
			notifySmartSelectionChanged()
		}
	}()
}

func persistServiceVerdicts(service string, outcomes map[string]serviceProbeOutcome) {
	if service == "" || len(outcomes) == 0 {
		return
	}
	cache := cachefile.Cache()
	if cache == nil || cache.DB == nil {
		return
	}
	for name, outcome := range outcomes {
		if !outcome.done || !outcome.verdict.known {
			continue
		}
		data, err := json.Marshal(persistedServiceVerdict{
			At:      outcome.verdict.at.UnixMilli(),
			Known:   outcome.verdict.known,
			Blocked: outcome.verdict.blocked,
			Region:  outcome.verdict.region,
		})
		if err != nil {
			continue
		}
		cache.SetSmartVerdict(smartVerdictCacheKey(service, name), data)
	}
}

// loadPersistedVerdicts restores still-valid service verdicts from cachefile so
// restarts avoid redundant cold-start probes.
func (s *Smart) loadPersistedVerdicts(now time.Time) {
	if s.service == "" {
		return
	}
	cache := cachefile.Cache()
	if cache == nil || cache.DB == nil {
		return
	}
	prefix := s.service + "\x00"
	raw := cache.SmartVerdicts()
	if len(raw) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, payload := range raw {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		name := key[len(prefix):]
		if existing, ok := s.verdicts[name]; ok && existing.known {
			continue
		}
		var item persistedServiceVerdict
		if err := json.Unmarshal(payload, &item); err != nil || !item.Known {
			continue
		}
		at := time.UnixMilli(item.At)
		if now.Sub(at) > serviceVerdictTTL {
			continue
		}
		if s.verdicts == nil {
			s.verdicts = make(map[string]serviceVerdict)
		}
		s.verdicts[name] = serviceVerdict{
			at:      at,
			known:   item.Known,
			blocked: item.Blocked,
			region:  item.Region,
		}
	}
}

// startPendingProbeLocked starts the manual re-tests that were queued while a
// run was in flight, skipping the members that run already covered. Callers
// must hold s.mu.
func (s *Smart) startPendingProbeLocked(members, probed []C.Proxy) {
	if len(s.forcePending) == 0 {
		return
	}
	for _, proxy := range probed {
		delete(s.forcePending, proxy.Name())
	}
	if len(s.forcePending) == 0 {
		s.forcePending = nil
		return
	}
	names := make([]string, 0, len(s.forcePending))
	for name := range s.forcePending {
		names = append(names, name)
	}
	s.forcePending = nil
	current := s.forcePendingCurrent
	s.forcePendingCurrent = ""
	targets := s.forceProbeTargetsLocked(members, names, current, time.Now())
	if len(targets) == 0 {
		return
	}
	log.Debugln("[Smart] %s: force probing %d queued member(s) for service %s", s.Name(), len(targets), s.service)
	s.startServiceProbeLocked(targets, members, true)
}

// applyProbeOutcomesLocked records one run's results and reports whether any
// member's usability or verdict state transitioned. Callers must hold s.mu.
func (s *Smart) applyProbeOutcomesLocked(outcomes map[string]serviceProbeOutcome, members []C.Proxy, now time.Time, forced bool) bool {
	current := make(map[string]struct{}, len(members))
	for _, proxy := range members {
		if proxy != nil {
			current[proxy.Name()] = struct{}{}
		}
	}
	changed := false
	for name, outcome := range outcomes {
		if s.attempts == nil {
			s.attempts = make(map[string]serviceProbeAttempt, len(outcomes))
		}
		previous := s.attempts[name]
		prevVerdict := s.verdicts[name]
		usable := outcome.done && outcome.verdict.known
		attempt := serviceProbeAttempt{at: now}
		if !outcome.done {
			attempt.fails = previous.fails + 1
		}
		if !usable {
			attempt.misses = previous.misses + 1
			attempt.manual = forced
		}
		s.attempts[name] = attempt
		if usable {
			if s.verdicts == nil {
				s.verdicts = make(map[string]serviceVerdict, len(outcomes))
			}
			s.verdicts[name] = outcome.verdict
			if !prevVerdict.known || prevVerdict.blocked != outcome.verdict.blocked || prevVerdict.region != outcome.verdict.region {
				changed = true
			}
		}
		if attempt.demoted() != previous.demoted() {
			changed = true
		}
		switch {
		case attempt.demoted() && !previous.demoted() && attempt.manual:
			log.Debugln("[Smart] service %s via %s: manual re-test without a usable verdict, demoted",
				s.service, name)
		case attempt.demoted() && !previous.demoted():
			log.Debugln("[Smart] service %s via %s: %d probes without an answer, demoted",
				s.service, name, attempt.fails)
		case !attempt.demoted() && previous.demoted():
			log.Debugln("[Smart] service %s via %s: probe answered again, usable", s.service, name)
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
	return changed
}

// serviceVerifiedLocked reports whether the member's last decidable probe
// confirmed it can serve the service and nothing has failed since. The group
// prefers these members over ones it never probed: a confirmation is stronger
// evidence than a low latency. Callers must hold s.mu (read or write).
func (s *Smart) serviceVerifiedLocked(name string, now time.Time) bool {
	if s.service == "" {
		return false
	}
	verdict, ok := s.verdicts[name]
	if !ok || !verdict.known || verdict.blocked || now.Sub(verdict.at) > serviceVerdictTTL {
		return false
	}
	if attempt, ok := s.attempts[name]; ok && (attempt.fails > 0 || attempt.manual) {
		return false
	}
	return true
}

// serviceUnusableLocked reports whether the member should stay out of the
// preferred pick: the last decidable probe refused it, a manual re-test got no
// usable verdict from it, or its requests keep failing without producing an
// answer at all. Callers must hold s.mu (read or write).
func (s *Smart) serviceUnusableLocked(name string, now time.Time) bool {
	if s.service == "" {
		return false
	}
	if attempt, ok := s.attempts[name]; ok && attempt.demoted() && now.Sub(attempt.at) < attempt.backoff() {
		return true
	}
	verdict, ok := s.verdicts[name]
	if !ok || !verdict.known {
		return false
	}
	if now.Sub(verdict.at) > serviceVerdictTTL {
		if verdict.blocked {
			if attempt, ok := s.attempts[name]; ok && attempt.misses > 0 && now.Sub(attempt.at) < attempt.backoff() {
				return true
			}
		}
		return false
	}
	return verdict.blocked
}
