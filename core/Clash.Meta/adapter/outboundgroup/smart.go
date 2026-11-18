package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/sockstat"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

const (
	smartEwmaAlpha          = 0.3     // weight of the newest real-connection sample
	smartUnknownScore       = 500.0   // ms, assumed latency before any sample exists
	smartMinScore           = 1.0     // ms
	smartMaxScore           = 30000.0 // ms
	smartPreferredGapRatio  = 0.15    // preferred set: scores within max(15%, 5ms) of the best
	smartPreferredGapMin    = 5.0     // ms
	smartSitePreferredGap   = 0.4     // widened gap for policies that recently worked for the site
	smartFailCooldown       = time.Minute
	smartFailCooldownMax    = 8 * time.Minute
	smartFailPenalty        = 600.0 // ms added while a policy is in failure cooldown
	smartLossPenaltyPerPct  = 50.0  // ~50ms per 1% retransmission, like Surge
	smartLossPenaltyMax     = 2000.0
	smartScoreHalfLife      = 10 * time.Minute
	smartLossHalfLife       = 10 * time.Minute
	smartUsageHalfLife      = 10 * time.Minute
	smartSiteMemoryTTL      = time.Hour
	smartSiteFailureTTL     = 10 * time.Minute
	smartSiteMemoryMaxSites = 512
	smartDialRetryLimit     = 3
	smartRankCacheTTL       = time.Second
)

type SmartOption struct {
	PolicyPriority string `group:"policy-priority,omitempty"`
	Service        string `group:"service,omitempty"`
}

type smartPriorityRule struct {
	pattern *regexp2.Regexp
	factor  float64
}

// smartPolicyState tracks the observed quality of one member policy.
type smartPolicyState struct {
	score        float64 // EWMA of first-response latency in ms; 0 means unknown
	lastSample   time.Time
	lossPenalty  float64 // EWMA of the retransmission penalty in ms
	lossUpdated  time.Time
	lastFail     time.Time
	failStreak   int
	usage        float64 // decayed session count, used for Now()
	usageUpdated time.Time
}

func (st *smartPolicyState) observeLatency(delayMs float64, now time.Time) {
	if delayMs < smartMinScore {
		delayMs = smartMinScore
	}
	if delayMs > smartMaxScore {
		delayMs = smartMaxScore
	}
	if st.score <= 0 {
		st.score = delayMs
	} else {
		st.score = st.score*(1-smartEwmaAlpha) + delayMs*smartEwmaAlpha
	}
	st.lastSample = now
	st.failStreak = 0
}

// observeFailure sharply worsens the policy: while the cooldown lasts it is
// ranked below healthy members, and it recovers through later tests or traffic.
// A failure that arrives after the previous cooldown already elapsed starts a
// new streak instead of extending a stale one forever.
func (st *smartPolicyState) observeFailure(now time.Time) {
	if !st.lastFail.IsZero() && now.Sub(st.lastFail) > st.failCooldown() {
		st.failStreak = 0
	}
	st.failStreak++
	st.lastFail = now
}

// failCooldown grows with consecutive failures, capped at smartFailCooldownMax.
func (st *smartPolicyState) failCooldown() time.Duration {
	if st.failStreak <= 0 {
		return smartFailCooldown
	}
	cooldown := smartFailCooldown
	for i := 1; i < st.failStreak; i++ {
		cooldown *= 2
		if cooldown >= smartFailCooldownMax {
			return smartFailCooldownMax
		}
	}
	return cooldown
}

// observeLoss folds an observed retransmission ratio (0.01 = 1%) into the
// policy's loss penalty.
func (st *smartPolicyState) observeLoss(ratio float64, now time.Time) {
	penalty := math.Min(ratio*100*smartLossPenaltyPerPct, smartLossPenaltyMax)
	if st.lossPenalty <= 0 {
		st.lossPenalty = penalty
	} else {
		st.lossPenalty = st.lossPenalty*0.5 + penalty*0.5
	}
	st.lossUpdated = now
}

// decayedLoss relaxes a stale loss penalty; without a timestamp the stored
// penalty is used unchanged.
func (st *smartPolicyState) decayedLoss(now time.Time) float64 {
	if st.lossUpdated.IsZero() {
		return st.lossPenalty
	}
	age := now.Sub(st.lossUpdated)
	if age <= 0 {
		return st.lossPenalty
	}
	return st.lossPenalty * math.Exp2(-age.Seconds()/smartLossHalfLife.Seconds())
}

// effectiveLatency is the policy's latency in ms: the EWMA sample relaxed
// toward the URL-test fallback by its age, clamped to the configured range.
func (st *smartPolicyState) effectiveLatency(fallback float64, now time.Time) float64 {
	score := fallback
	if st.score > 0 && !st.lastSample.IsZero() {
		age := now.Sub(st.lastSample)
		if age < 0 {
			age = 0
		}
		// A stale sample relaxes toward the current URL-test fallback instead of
		// pinning the policy to an old measurement.
		score = fallback + (st.score-fallback)*math.Exp2(-age.Seconds()/smartScoreHalfLife.Seconds())
	}
	if score < smartMinScore {
		score = smartMinScore
	}
	if score > smartMaxScore {
		score = smartMaxScore
	}
	return score
}

// penalty is the loss plus failure penalty in ms. It is added after the
// policy-priority factor has been applied, so a factor below 1 cannot soften
// an observed penalty.
func (st *smartPolicyState) penalty(now time.Time) float64 {
	penalty := st.decayedLoss(now)
	if st.failStreak > 0 && now.Sub(st.lastFail) < st.failCooldown() {
		penalty += smartFailPenalty * float64(st.failStreak)
	}
	return penalty
}

// effectiveScore is the latency plus the loss and failure penalties, before
// the policy-priority factor; factor 1 keeps the historical weighting.
func (st *smartPolicyState) effectiveScore(fallback float64, now time.Time) float64 {
	return st.scored(fallback, 1.0, now)
}

// scored applies the policy-priority factor to the latency only: penalties
// describe observed damage and keep their full weight whatever the factor is.
func (st *smartPolicyState) scored(fallback, factor float64, now time.Time) float64 {
	return st.effectiveLatency(fallback, now)*factor + st.penalty(now)
}

func (st *smartPolicyState) bumpUsage(now time.Time) {
	st.usage = st.decayedUsage(now) + 1
	st.usageUpdated = now
}

func (st *smartPolicyState) decayedUsage(now time.Time) float64 {
	if st.usageUpdated.IsZero() {
		return 0
	}
	elapsed := now.Sub(st.usageUpdated)
	if elapsed <= 0 {
		return st.usage
	}
	return st.usage * math.Exp2(-elapsed.Seconds()/smartUsageHalfLife.Seconds())
}

type smartSiteEntry struct {
	lastSuccess time.Time
	lastFailure time.Time
}

type smartSiteRecord struct {
	updated time.Time
	proxies map[string]*smartSiteEntry
}

// smartRankCache is a short-lived, read-only score ranking shared by the
// connections of one group. Site memory is not part of it: that is
// per-destination and applied by the caller from the current site record.
type smartRankCache struct {
	proxies []C.Proxy
	builtAt time.Time
	gen     uint64
	ranked  []smartCandidate
}

type Smart struct {
	*GroupBase
	disableUDP     bool
	testUrl        string
	expectedStatus string

	mu        sync.Mutex
	selected  string
	states    map[string]*smartPolicyState
	sites     map[string]*smartSiteRecord
	priority  []smartPriorityRule
	rankCache *smartRankCache
	rankGen   uint64

	// service is empty unless the group ranks members by their ability to
	// reach one service; verdicts holds the last decidable probe result per
	// member, attempts the last probe try, decidable or not.
	service   string
	verdicts  map[string]serviceVerdict
	attempts  map[string]time.Time
	lastProbe time.Time
	probing   bool
}

// Now implements ProxyGroup: the pinned policy, else the most-used policy in
// the recent period, else the best-scored one. Like Surge, the reported
// selection is not necessarily the policy every new connection will use.
func (s *Smart) Now() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	proxies := s.GetProxies(false)
	if s.selected != "" {
		for _, proxy := range proxies {
			if proxy.Name() == s.selected {
				return s.selected
			}
		}
	}

	now := time.Now()
	bestName := ""
	bestUsage := 0.0
	bestScoreName := ""
	bestScore := math.MaxFloat64
	blockedScoreName := ""
	blockedScore := math.MaxFloat64
	for _, proxy := range proxies {
		name := proxy.Name()
		st := s.states[name]
		if st != nil {
			if usage := st.decayedUsage(now); usage > bestUsage {
				bestUsage = usage
				bestName = name
			}
		}
		score := s.scoreOf(proxy, st, now)
		if s.serviceBlockedLocked(name, now) {
			if score < blockedScore {
				blockedScore = score
				blockedScoreName = name
			}
			continue
		}
		if score < bestScore {
			bestScore = score
			bestScoreName = name
		}
	}
	// A policy that still carries recent traffic can have failed its service
	// probe since; report the best usable one so the panel never advertises a
	// member the group will not pick first.
	if bestName != "" && (bestScoreName == "" || !s.serviceBlockedLocked(bestName, now)) {
		return bestName
	}
	if bestScoreName != "" {
		return bestScoreName
	}
	return blockedScoreName
}

// smartNodeFailure reports whether a first-write error is evidence against the
// node. Caller-side cancellation and unsupported capabilities say nothing about
// the node's health; a deadline here has no caller context to inspect, so it is
// treated as a node failure.
func smartNodeFailure(err error) bool {
	return err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, C.ErrNotSupport)
}

// smartDialFailure reports whether a dial error is evidence against the node.
// A deadline from a live caller context is the normal signal for a hanging
// node, while an error after the caller's context is done says nothing about
// the node. ErrNotSupport is a capability mismatch, not a health signal.
func smartDialFailure(ctx context.Context, err error) bool {
	if err == nil || errors.Is(err, C.ErrNotSupport) {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	return true
}

// DialContext implements C.ProxyAdapter
func (s *Smart) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	candidates := s.orderedCandidates(metadata, true)

	var lastErr error
	var lastProxy C.Proxy
	attempts := 0
	for _, proxy := range candidates {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}

		dialStart := time.Now()
		conn, err := proxy.DialContext(ctx, metadata)
		if err != nil {
			lastErr = err
			lastProxy = proxy
			attempts++
			if smartDialFailure(ctx, err) {
				s.reportFailure(proxy.Name(), metadata)
			}
			// Only the caller's context ending stops the retry loop. A node's
			// own dial timeout is a failure worth trying the next member for.
			if ctx.Err() != nil {
				break
			}
			if attempts >= smartDialRetryLimit {
				break
			}
			log.Debugln("[Smart] %s dial via %s failed: %v, fallback to next candidate", s.Name(), proxy.Name(), err)
			continue
		}
		dialDone := time.Now()
		dialLatency := dialDone.Sub(dialStart)
		if dialLatency < 0 {
			dialLatency = 0
		}

		s.reportUsed(proxy.Name())
		conn.AppendToChains(s)

		if N.NeedHandshake(conn) {
			conn = callback.NewFirstWriteCallBackConn(conn, func(err error) {
				if err == nil {
					s.onDialSuccess()
					return
				}
				if smartNodeFailure(err) {
					s.onDialFailed(proxy.Type(), err, s.healthCheck)
				}
			})
		}

		return newSmartConn(conn, s, proxy.Name(), metadata, dialDone, dialLatency), nil
	}

	if lastErr == nil {
		lastErr = errors.New("smart: no available proxy")
	} else if lastProxy != nil && smartDialFailure(ctx, lastErr) {
		// Retrying one request through several members is one group-level
		// failure, not one per candidate.
		s.onDialFailed(lastProxy.Type(), lastErr, s.healthCheck)
	}
	return nil, lastErr
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Smart) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	candidates := s.orderedCandidates(metadata, true)

	var lastErr error
	var lastProxy C.Proxy
	attempts := 0
	for _, proxy := range candidates {
		if !proxy.SupportUDP() {
			continue
		}
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}

		pc, err := proxy.ListenPacketContext(ctx, metadata)
		if err != nil {
			lastErr = err
			lastProxy = proxy
			attempts++
			if smartDialFailure(ctx, err) {
				s.reportFailure(proxy.Name(), metadata)
			}
			if ctx.Err() != nil {
				break
			}
			if attempts >= smartDialRetryLimit {
				break
			}
			log.Debugln("[Smart] %s udp via %s failed: %v, fallback to next candidate", s.Name(), proxy.Name(), err)
			continue
		}

		s.reportUsed(proxy.Name())
		pc.AppendToChains(s)
		return pc, nil
	}

	if lastErr == nil {
		return nil, C.ErrNotSupport
	}
	if lastProxy != nil && smartDialFailure(ctx, lastErr) {
		s.onDialFailed(lastProxy.Type(), lastErr, s.healthCheck)
	}
	return nil, lastErr
}

// SupportUDP implements C.ProxyAdapter
func (s *Smart) SupportUDP() bool {
	if s.disableUDP {
		return false
	}
	for _, proxy := range s.GetProxies(false) {
		if proxy != nil && proxy.SupportUDP() {
			return true
		}
	}
	return false
}

// IsL3Protocol implements C.ProxyAdapter
func (s *Smart) IsL3Protocol(metadata *C.Metadata) bool {
	proxy := s.representativeProxy(metadata, false)
	if proxy == nil {
		return false
	}
	return proxy.IsL3Protocol(metadata)
}

// Unwrap implements C.ProxyAdapter
func (s *Smart) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	if proxy := s.representativeProxy(metadata, touch); proxy != nil {
		return proxy
	}
	return s.EmptyFallback()
}

// representativeProxy returns the deterministic policy that stands for the
// group: the pinned policy when it is still a member, otherwise the
// best-scored alive policy, otherwise the best-scored policy. Capability
// queries and Unwrap use it so the answer never depends on a random pick.
func (s *Smart) representativeProxy(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := s.GetProxies(touch)
	if len(proxies) == 0 {
		return nil
	}

	ranked := s.rankedCandidates(proxies, time.Now())
	if len(ranked) == 0 {
		return nil
	}

	s.mu.Lock()
	pinned := s.selected
	s.mu.Unlock()

	if pinned != "" {
		for _, item := range ranked {
			if item.proxy.Name() == pinned {
				return item.proxy
			}
		}
	}
	for _, item := range ranked {
		if item.alive && !item.blocked {
			return item.proxy
		}
	}
	return ranked[0].proxy
}

// MarshalJSON implements C.ProxyAdapter
func (s *Smart) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range s.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":           s.Type().String(),
		"now":            s.Now(),
		"all":            all,
		"testUrl":        s.testUrl,
		"expectedStatus": s.expectedStatus,
		"fixed":          s.fixedName(),
		"hidden":         s.Hidden(),
		"icon":           s.Icon(),
		"emptyFallback":  s.EmptyFallback().Name(),
	})
}

func (s *Smart) fixedName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selected
}

func (s *Smart) Set(name string) error {
	for _, proxy := range s.GetProxies(false) {
		if proxy.Name() == name {
			s.ForceSet(name)
			return nil
		}
	}
	return errors.New("proxy not exist")
}

func (s *Smart) ForceSet(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selected = name
}

func (s *Smart) Providers() []P.ProxyProvider {
	return s.providers
}

func (s *Smart) Proxies() []C.Proxy {
	return s.GetProxies(false)
}

func (s *Smart) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	return s.GroupBase.URLTest(ctx, s.testUrl, expectedStatus)
}

func (s *Smart) healthCheck() {
	s.GroupBase.healthCheck()
	// AliveForTestUrl consults each proxy's own state; snapshot it before taking
	// s.mu so this lock is never held while calling into a proxy.
	alive := make(map[string]bool)
	proxies := s.GetProxies(false)
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}
		alive[proxy.Name()] = proxy.AliveForTestUrl(s.testUrl)
	}
	s.mu.Lock()
	for name, st := range s.states {
		if alive[name] {
			st.failStreak = 0
		}
	}
	s.invalidateRankCacheLocked()
	s.mu.Unlock()

	s.maybeProbeService(proxies)
}

type smartCandidate struct {
	proxy   C.Proxy
	score   float64
	alive   bool
	blocked bool // last service probe says this member cannot serve the service
}

// siteStatus classifies a policy for one destination using a snapshot of the
// group's site memory. A hit widens the preferred gap, a miss keeps the policy
// out of the first pick. Both are derived from the live record, so site memory
// does not need to be part of the cached ranking.
func siteStatus(entries map[string]smartSiteEntry, name string, now time.Time) (hit, miss bool) {
	if entries == nil {
		return false, false
	}
	entry, ok := entries[name]
	if !ok {
		return false, false
	}
	successFresh := !entry.lastSuccess.IsZero() && now.Sub(entry.lastSuccess) < smartSiteMemoryTTL
	failureFresh := !entry.lastFailure.IsZero() && now.Sub(entry.lastFailure) < smartSiteFailureTTL
	hit = successFresh && (!failureFresh || entry.lastSuccess.After(entry.lastFailure))
	miss = failureFresh && !hit
	return hit, miss
}

// stickySitePick returns the preferred member that most recently served the
// site. The pick is self-reinforcing: while the member keeps answering, its
// success stays the newest, and it drops out as soon as it fails, falls out of
// the preferred band, or the service probe demotes it.
func stickySitePick(ranked []smartCandidate, preferred []int, entries map[string]smartSiteEntry, now time.Time) (int, bool) {
	sticky := -1
	var newest time.Time
	for _, idx := range preferred {
		name := ranked[idx].proxy.Name()
		if hit, _ := siteStatus(entries, name, now); !hit {
			continue
		}
		if success := entries[name].lastSuccess; sticky < 0 || success.After(newest) {
			sticky, newest = idx, success
		}
	}
	return sticky, sticky >= 0
}

// sameProxyList reports whether both slices share a backing array. GroupBase
// rebuilds its proxy slice when a provider version changes, so backing-array
// identity notices membership updates without comparing every element.
func sameProxyList(a, b []C.Proxy) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// rankedCandidates returns the group's members ordered by score. The result is
// cached for smartRankCacheTTL and shared between connections; callers must
// treat it as read-only. Rebuilding the ranking per connection would repeat the
// same score reads and sort for every socket in a page load, while the
// underlying samples decay over minutes, not milliseconds.
func (s *Smart) rankedCandidates(proxies []C.Proxy, now time.Time) []smartCandidate {
	s.mu.Lock()
	if cache := s.rankCache; cache != nil &&
		cache.gen == s.rankGen &&
		now.Sub(cache.builtAt) < smartRankCacheTTL &&
		sameProxyList(cache.proxies, proxies) {
		ranked := cache.ranked
		s.mu.Unlock()
		return ranked
	}
	gen := s.rankGen
	candidates := make([]smartCandidate, 0, len(proxies))
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}
		st := s.states[proxy.Name()]
		candidates = append(candidates, smartCandidate{
			proxy:   proxy,
			score:   s.scoreOf(proxy, st, now),
			alive:   proxy.AliveForTestUrl(s.testUrl),
			blocked: s.serviceBlockedLocked(proxy.Name(), now),
		})
	}
	s.mu.Unlock()

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].score < candidates[j].score
	})

	s.mu.Lock()
	// A failure or health check invalidated the ranking while it was being
	// built; do not resurrect the stale order.
	if s.rankGen == gen {
		s.rankCache = &smartRankCache{
			proxies: proxies,
			builtAt: now,
			gen:     gen,
			ranked:  candidates,
		}
	}
	s.mu.Unlock()
	return candidates
}

// orderedCandidates returns the policies to try for one request: the preferred
// pick first (a random member of the policies closest to the best score, or
// the pinned one), then the remaining healthy policies by score, then the ones
// a service probe demoted, then the failed ones, so a dead connection can fall
// back to the next candidate.
func (s *Smart) orderedCandidates(metadata *C.Metadata, touch bool) []C.Proxy {
	proxies := s.GetProxies(touch)
	if len(proxies) == 0 {
		return nil
	}
	// Connections are the trigger to learn which members can serve the
	// service; the selection skips members with a fresh verdict, so a group
	// that already knows its members dials nothing extra.
	s.maybeProbeService(proxies)

	now := time.Now()
	ranked := s.rankedCandidates(proxies, now)
	if len(ranked) == 0 {
		return nil
	}
	siteKey := getKey(metadata)

	s.mu.Lock()
	var siteEntries map[string]smartSiteEntry
	if siteKey != "" {
		if record := s.sites[siteKey]; record != nil {
			siteEntries = make(map[string]smartSiteEntry, len(record.proxies))
			for name, entry := range record.proxies {
				siteEntries[name] = *entry
			}
		}
	}
	pinned := s.selected
	s.mu.Unlock()

	firstPick := -1
	if pinned != "" {
		for i, item := range ranked {
			if item.proxy.Name() == pinned {
				firstPick = i
				break
			}
		}
	}

	if firstPick < 0 {
		best := 0.0
		hasBest := false
		for _, item := range ranked {
			if !item.alive || item.blocked {
				continue
			}
			if _, miss := siteStatus(siteEntries, item.proxy.Name(), now); miss {
				continue
			}
			best = item.score
			hasBest = true
			break
		}

		var preferred []int
		if hasBest {
			baseGap := math.Max(best*smartPreferredGapRatio, smartPreferredGapMin)
			for i, item := range ranked {
				if !item.alive || item.blocked {
					continue
				}
				hit, miss := siteStatus(siteEntries, item.proxy.Name(), now)
				if miss {
					continue
				}
				gap := baseGap
				if hit {
					gap = math.Max(best*smartSitePreferredGap, smartPreferredGapMin)
				}
				if item.score <= best+gap {
					preferred = append(preferred, i)
				}
			}
		}

		if len(preferred) > 0 {
			// Service groups pin the destination to the member that most recently
			// served it: Google and OpenAI tie sessions to the egress IP, so
			// rotating inside the preferred set costs more than the load it
			// spreads. General groups keep the rotation.
			if s.service != "" {
				if sticky, ok := stickySitePick(ranked, preferred, siteEntries, now); ok {
					firstPick = sticky
				}
			}
			if firstPick < 0 {
				firstPick = preferred[rand.Intn(len(preferred))]
			}
		} else {
			// nothing preferred: still try a live policy before a dead one, even
			// if every live policy is suspended for this site.
			firstPick = 0
			healthy := false
			for i, item := range ranked {
				if item.alive && !item.blocked {
					firstPick = i
					healthy = true
					break
				}
			}
			if !healthy {
				// Every live member is service-blocked; a blocked member is still a
				// better first pick than a member whose URL test failed.
				for i, item := range ranked {
					if item.alive {
						firstPick = i
						break
					}
				}
			}
		}
	}

	order := make([]C.Proxy, 0, len(ranked))
	if firstPick >= 0 {
		first := ranked[firstPick]
		hit, miss := siteStatus(siteEntries, first.proxy.Name(), now)
		order = append(order, first.proxy)
		log.Debugln("[Smart] %s picked %s (score %.1fms, siteHit=%t, siteMiss=%t, site=%q)",
			s.Name(), first.proxy.Name(), first.score, hit, miss, siteKey)
	}

	for i, item := range ranked {
		if i == firstPick || !item.alive || item.blocked {
			continue
		}
		order = append(order, item.proxy)
	}
	// A member that cannot serve the service is still a better fallback than a
	// member whose last URL test failed.
	for i, item := range ranked {
		if i == firstPick || !item.alive || !item.blocked {
			continue
		}
		order = append(order, item.proxy)
	}
	for i, item := range ranked {
		if i == firstPick || item.alive {
			continue
		}
		order = append(order, item.proxy)
	}
	return order
}

// scoreOf combines the policy's EWMA latency (seeded by URL test results) with
// its loss and failure penalties. The policy-priority factor scales the
// latency only, so a premium factor cannot also discount a failure penalty.
func (s *Smart) scoreOf(proxy C.Proxy, st *smartPolicyState, now time.Time) float64 {
	fallback := smartUnknownScore
	if delay := proxy.LastDelayForTestUrl(s.testUrl); delay != 0xffff && delay > 0 {
		fallback = float64(delay)
	}
	factor := s.priorityFactor(proxy.Name())
	if st == nil {
		return fallback * factor
	}
	return st.scored(fallback, factor, now)
}

func (s *Smart) priorityFactor(name string) float64 {
	for _, rule := range s.priority {
		if matched, _ := rule.pattern.MatchString(name); matched {
			return rule.factor
		}
	}
	return 1.0
}

func (s *Smart) stateOf(name string) *smartPolicyState {
	st, ok := s.states[name]
	if !ok {
		st = &smartPolicyState{}
		s.states[name] = st
	}
	return st
}

func (s *Smart) reportLatency(name string, metadata *C.Metadata, delayMs float64) {
	now := time.Now()
	s.mu.Lock()
	if delayMs < smartMinScore {
		delayMs = smartMinScore
	}
	// A response this late is more likely a slow endpoint or long-poll than a
	// useful node-quality sample. Keep the site success, drop the score sample.
	if delayMs <= smartMaxScore {
		s.stateOf(name).observeLatency(delayMs, now)
	}
	s.rememberSite(metadata, name, true, now)
	s.mu.Unlock()
}

func (s *Smart) reportFailure(name string, metadata *C.Metadata) {
	now := time.Now()
	s.mu.Lock()
	s.stateOf(name).observeFailure(now)
	s.rememberSite(metadata, name, false, now)
	s.invalidateRankCacheLocked()
	s.mu.Unlock()
}

// invalidateRankCacheLocked forces the next connection to rebuild the ranking;
// the caller must hold s.mu. Slow-moving samples (latency, loss) are left to the
// TTL, so a burst of connections can still share one ranking.
func (s *Smart) invalidateRankCacheLocked() {
	s.rankGen++
	s.rankCache = nil
}

func (s *Smart) reportRetransmit(name string, delta sockstat.TCPStats, baseOK bool) {
	if !baseOK {
		return
	}
	ratio, ok := delta.RetransmitRatio()
	if !ok {
		return
	}
	s.mu.Lock()
	s.stateOf(name).observeLoss(ratio, time.Now())
	s.mu.Unlock()
}

func (s *Smart) reportUsed(name string) {
	now := time.Now()
	s.mu.Lock()
	s.stateOf(name).bumpUsage(now)
	s.mu.Unlock()
}

// rememberSite records the per-site outcome that drives the group's site
// memory; the caller must hold s.mu.
func (s *Smart) rememberSite(metadata *C.Metadata, name string, success bool, now time.Time) {
	key := getKey(metadata)
	if key == "" || name == "" {
		return
	}

	record, ok := s.sites[key]
	if !ok {
		if len(s.sites) >= smartSiteMemoryMaxSites {
			s.pruneSites(now)
		}
		if len(s.sites) >= smartSiteMemoryMaxSites {
			s.evictOldestSite()
		}
		record = &smartSiteRecord{proxies: make(map[string]*smartSiteEntry)}
		s.sites[key] = record
	}

	entry, ok := record.proxies[name]
	if !ok {
		entry = &smartSiteEntry{}
		record.proxies[name] = entry
	}
	if success {
		entry.lastSuccess = now
	} else {
		entry.lastFailure = now
	}
	record.updated = now
}

// pruneSites drops records untouched for the success TTL, expired per-proxy
// entries, and records that became empty; the caller must hold s.mu.
func (s *Smart) pruneSites(now time.Time) {
	for key, record := range s.sites {
		if !record.updated.IsZero() && now.Sub(record.updated) > smartSiteMemoryTTL {
			delete(s.sites, key)
			continue
		}
		for name, entry := range record.proxies {
			successFresh := !entry.lastSuccess.IsZero() && now.Sub(entry.lastSuccess) < smartSiteMemoryTTL
			failureFresh := !entry.lastFailure.IsZero() && now.Sub(entry.lastFailure) < smartSiteFailureTTL
			if !successFresh && !failureFresh {
				delete(record.proxies, name)
			}
		}
		if len(record.proxies) == 0 {
			delete(s.sites, key)
		}
	}
}

// evictOldestSite drops the least-recently-updated record to make room for a
// new site; the caller must hold s.mu.
func (s *Smart) evictOldestSite() {
	oldestKey := ""
	var oldest time.Time
	for key, record := range s.sites {
		if oldestKey == "" || record.updated.Before(oldest) {
			oldestKey = key
			oldest = record.updated
		}
	}
	if oldestKey != "" {
		delete(s.sites, oldestKey)
	}
}

func parsePolicyPriority(value string) ([]smartPriorityRule, error) {
	var rules []smartPriorityRule
	for _, entry := range strings.Split(value, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idx := strings.LastIndex(entry, ":")
		if idx <= 0 {
			return nil, fmt.Errorf("invalid policy-priority entry %q, want \"pattern:factor\"", entry)
		}
		pattern := strings.TrimSpace(entry[:idx])
		factorText := strings.TrimSpace(entry[idx+1:])
		factor, err := strconv.ParseFloat(factorText, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid policy-priority factor %q: %w", factorText, err)
		}
		if factor <= 0 || math.IsInf(factor, 0) || math.IsNaN(factor) {
			return nil, fmt.Errorf("invalid policy-priority factor %q: must be positive", factorText)
		}
		patternReg, err := regexp2.Compile(pattern, regexp2.None)
		if err != nil {
			return nil, fmt.Errorf("invalid policy-priority pattern %q: %w", pattern, err)
		}
		rules = append(rules, smartPriorityRule{pattern: patternReg, factor: factor})
	}
	return rules, nil
}

// smartConn wraps a member connection and feeds the group's scorer: it reports
// the first-response latency on the first inbound byte, a failure when a request
// was written but no data arrived, and the socket's retransmission counters
// when it closes.
type smartConn struct {
	C.Conn

	smart       *Smart
	proxyName   string
	metadata    *C.Metadata
	dialDone    time.Time     // dial completion, the earliest point latency can start
	dialLatency time.Duration // time spent in proxy.DialContext

	writeMutex sync.Mutex
	firstWrite time.Time // completion of the first outbound write
	wroteData  atomic.Bool

	base   sockstat.TCPStats
	baseOK bool

	firstByteOnce sync.Once
	gotData       atomic.Bool
	closeOnce     sync.Once
}

func newSmartConn(conn C.Conn, smart *Smart, proxyName string, metadata *C.Metadata, dialDone time.Time, dialLatency time.Duration) C.Conn {
	sc := &smartConn{
		Conn:        conn,
		smart:       smart,
		proxyName:   proxyName,
		metadata:    metadata,
		dialDone:    dialDone,
		dialLatency: dialLatency,
	}
	sc.base, sc.baseOK = sockstat.Sample(conn)
	return sc
}

func (c *smartConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.markFirstByte()
	}
	return n, err
}

func (c *smartConn) ReadBuffer(buffer *buf.Buffer) error {
	err := c.Conn.ReadBuffer(buffer)
	if buffer.Len() > 0 {
		c.markFirstByte()
	}
	return err
}

func (c *smartConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.markWrite()
	}
	return n, err
}

func (c *smartConn) WriteBuffer(buffer *buf.Buffer) error {
	size := buffer.Len()
	err := c.Conn.WriteBuffer(buffer)
	if err == nil && size > 0 {
		c.markWrite()
	}
	return err
}

func (c *smartConn) Close() error {
	c.closeOnce.Do(func() {
		// the socket must still be open to read its counters
		if stats, ok := sockstat.Sample(c.Conn); ok {
			c.smart.reportRetransmit(c.proxyName, stats.Sub(c.base), c.baseOK)
		}
		// Only an unanswered request is evidence against the node: a connection
		// closed before any write (browser preconnect, canceled request) says
		// nothing about its health.
		if c.wroteData.Load() && !c.gotData.Load() {
			c.smart.reportFailure(c.proxyName, c.metadata)
		}
	})
	return c.Conn.Close()
}

func (c *smartConn) markWrite() {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.firstWrite.IsZero() {
		c.firstWrite = time.Now()
	}
	c.wroteData.Store(true)
}

// firstResponseDelay keeps real samples on the same basis as URLTest: the
// caller's think time after the dial is excluded, but the proxy dial leg is
// added back so a real sample and a LastDelayForTestUrl seed are comparable.
func firstResponseDelay(base, firstByte time.Time, dialLatency time.Duration) time.Duration {
	delay := firstByte.Sub(base) + dialLatency
	if delay < 0 {
		return 0
	}
	return delay
}

func (c *smartConn) markFirstByte() {
	c.firstByteOnce.Do(func() {
		c.gotData.Store(true)
		c.writeMutex.Lock()
		base := c.dialDone
		if c.firstWrite.After(base) {
			base = c.firstWrite
		}
		c.writeMutex.Unlock()
		delayMs := float64(firstResponseDelay(base, time.Now(), c.dialLatency)) / float64(time.Millisecond)
		c.smart.reportLatency(c.proxyName, c.metadata, delayMs)
	})
}

func (c *smartConn) Upstream() any {
	return c.Conn
}

var _ C.Conn = (*smartConn)(nil)

func NewSmart(option GroupCommonOption, smartOption SmartOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (*Smart, error) {
	priority, err := parsePolicyPriority(smartOption.PolicyPriority)
	if err != nil {
		return nil, err
	}
	service, err := normalizeServiceName(smartOption.Service)
	if err != nil {
		// A published script can reach an older core before the next release; a
		// typo must degrade to plain scoring instead of breaking the config.
		log.Warnln("[Smart] %s: %v, service ranking disabled", option.Name, err)
		service = ""
	}
	return &Smart{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.Smart,
			Hidden:         option.Hidden,
			Icon:           option.Icon,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			EmptyFallback:  emptyFallback,
			Providers:      providers,
		}),
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		states:         make(map[string]*smartPolicyState),
		sites:          make(map[string]*smartSiteRecord),
		priority:       priority,
		service:        service,
		verdicts:       make(map[string]serviceVerdict),
		attempts:       make(map[string]time.Time),
	}, nil
}
