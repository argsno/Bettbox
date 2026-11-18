package outboundgroup

import (
	"context"
	"fmt"
	"io"
	"regexp"
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
	serviceProbeTimeout  = 5 * time.Second
	serviceProbeWorkers  = 8
	serviceProbeInterval = 5 * time.Minute
	serviceVerdictTTL    = 20 * time.Minute
	serviceProbeMaxBody  = 256 << 10
)

type servicePreset struct {
	url string
	// trace reads Cloudflare's /cdn-cgi/trace key=value body; otherwise the body
	// is a service page that only reveals the region through its payload.
	trace   bool
	blocked map[string]struct{}
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
		url: "https://gemini.google.com/",
		blocked: serviceRegionSet(
			"CN", "CHN", "RU", "RUS", "BY", "BLR", "IR", "IRN", "KP", "PRK",
			"SY", "SYR", "CU", "CUB", "VE", "VEN", "MM", "MMR", "SD", "SDN",
			"AF", "AFG", "SS", "SSD", "YE", "YEM", "ZW", "ZWE",
		),
	},
}

var serviceAliases = map[string]string{
	"":              "",
	"openai":        "openai",
	"chatgpt":       "openai",
	"google-gemini": "google-gemini",
	"gemini":        "google-gemini",
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

var geminiRegionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`,2,1,200,"([A-Z]{3})"`),
	regexp.MustCompile(`\[1,null,null,\d+,\d+,"([A-Z]{3})"`),
}

var geminiUnavailablePhrases = []string{
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

	for _, pattern := range geminiRegionPatterns {
		if match := pattern.FindStringSubmatch(body); match != nil {
			verdict.region = match[1]
			break
		}
	}
	verdict.known = true
	lowerBody := strings.ToLower(body)
	_, blockedRegion := preset.blocked[strings.ToUpper(verdict.region)]
	if status != 200 ||
		strings.Contains(finalURL, "sorry.google.com") ||
		blockedRegion {
		verdict.blocked = true
		return verdict
	}
	for _, phrase := range geminiUnavailablePhrases {
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

func (s *Smart) probeServiceMembers(proxies []C.Proxy, service string) map[string]serviceVerdict {
	sem := make(chan struct{}, serviceProbeWorkers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	verdicts := make(map[string]serviceVerdict, len(proxies))
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
			if err != nil {
				// A failed probe says nothing about the member's region, so the
				// previous verdict keeps its weight until it expires.
				return
			}
			log.Debugln("[Smart] service %s via %s: region=%q known=%t blocked=%t",
				service, proxy.Name(), verdict.region, verdict.known, verdict.blocked)
			mu.Lock()
			verdicts[proxy.Name()] = verdict
			mu.Unlock()
		}()
	}
	wg.Wait()
	return verdicts
}

// maybeProbeService probes on the first connection after the throttle window
// and on dial-failure health checks: probing every member costs one small
// request each, so a run in flight or a fresh result skips it.
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
	s.probing = true
	s.lastProbe = now
	s.mu.Unlock()

	go func() {
		verdicts := s.probeServiceMembers(proxies, s.service)
		s.mu.Lock()
		s.probing = false
		s.mergeVerdictsLocked(verdicts)
		s.invalidateRankCacheLocked()
		s.mu.Unlock()
	}()
}

// mergeVerdictsLocked keeps undecidable results out of the map so a member that
// was already demoted is not silently promoted; the old entry expires on its TTL.
// Callers must hold s.mu.
func (s *Smart) mergeVerdictsLocked(verdicts map[string]serviceVerdict) {
	for name, verdict := range verdicts {
		if !verdict.known {
			continue
		}
		if s.verdicts == nil {
			s.verdicts = make(map[string]serviceVerdict, len(verdicts))
		}
		s.verdicts[name] = verdict
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
