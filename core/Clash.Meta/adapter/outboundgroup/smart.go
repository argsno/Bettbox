package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
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
	smartEwmaSpikeAlpha     = 0.12    // conservative weight for sudden outlier latency spikes
	smartEwmaStaleAlpha     = 0.5     // faster adaptation after a policy was idle past half-life
	smartUnknownScore       = 500.0   // ms, assumed latency before any sample exists
	smartMinScore           = 1.0     // ms
	smartMaxScore           = 30000.0 // ms, hard clamp for stored/aged scores
	smartSampleCap          = 5000.0  // ms, real-traffic TTFB above this is dropped (slow backend/LLM/long-poll)
	smartSpikeFloor         = 1500.0  // ms, minimum ceiling before Winsorizing a single spike
	smartSpikeMultiplier    = 3.0     // single sample clamped to max(score*3, 1500ms)
	smartPreferredGapRatio  = 0.15    // preferred set: scores within max(15%, 5ms) of the best
	smartPreferredGapMin    = 5.0     // ms
	smartSitePreferredGap   = 0.4     // widened gap for policies that recently worked for the site
	smartFailCooldown       = time.Minute
	smartFailCooldownMax    = 8 * time.Minute
	smartFailPenalty        = 600.0 // ms added while a policy is in failure cooldown
	smartLossPenaltyPerPct  = 50.0  // ~50ms per 1% retransmission, like Surge
	smartLossPenaltyMax     = 2000.0
	smartJitterBaseMs       = 30.0  // ms of RTTVar tolerated without jitter penalty
	smartJitterWeight       = 0.5   // ms penalty per ms of RTTVar above smartJitterBaseMs
	smartJitterPenaltyMax   = 300.0 // ms
	smartScoreHalfLife      = 10 * time.Minute
	smartLossHalfLife       = 10 * time.Minute
	smartUsageHalfLife      = 10 * time.Minute
	smartSiteMemoryTTL      = time.Hour
	smartSiteFailureTTL     = 10 * time.Minute
	smartSiteMemoryMaxSites = 512
	smartDialRetryLimit     = 3
	smartDialMinBudget      = 500 * time.Millisecond
	smartDialFirstMaxBudget = 2 * time.Second
	smartHedgeMinDelay      = 300 * time.Millisecond
	smartHedgeMaxDelay      = time.Second
	smartRankCacheTTL       = time.Second
	smartExploreEvery       = 25 // general groups probe one non-band alive member every N picks
	smartWakeupCooldown     = 2 * time.Minute
)

// smartUnansweredMinWait prevents fast caller-side cancellations (e.g. closed
// tabs, canceled prefetch, fire-and-forget UDP) from penalizing healthy nodes
// when no read error occurred.
var smartUnansweredMinWait = 200 * time.Millisecond

// smartHedgeDelayFn computes how long DialContext waits on the first candidate
// before hedging with the second candidate. Overridable in tests.
var smartHedgeDelayFn = defaultSmartHedgeDelay

func defaultSmartHedgeDelay(firstScore float64) time.Duration {
	if firstScore <= 0 {
		return smartHedgeMinDelay
	}
	d := time.Duration(firstScore*2) * time.Millisecond
	if d < smartHedgeMinDelay {
		return smartHedgeMinDelay
	}
	if d > smartHedgeMaxDelay {
		return smartHedgeMaxDelay
	}
	return d
}

// SmartSelectionChangedHook is invoked asynchronously when a Smart group's
// routing state transitions (probe verdict update or node failure) so the UI
// can refresh immediately without waiting for polling timers.
var SmartSelectionChangedHook func()

func notifySmartSelectionChanged() {
	hook := SmartSelectionChangedHook
	if hook != nil {
		go hook()
	}
}

type SmartOption struct {
	PolicyPriority string `group:"policy-priority,omitempty"`
	Service        string `group:"service,omitempty"`
	Pin            string `group:"pin,omitempty"`
}

// SmartMemberSnapshot exposes compact per-member state for diagnostics and UI.
type SmartMemberSnapshot struct {
	Score    int    `json:"score"`
	Verified bool   `json:"verified,omitempty"`
	Blocked  bool   `json:"blocked,omitempty"`
	Region   string `json:"region,omitempty"`
	Cooling  bool   `json:"cooling,omitempty"`
}

// SmartSnapshot summarizes a Smart group's runtime state.
type SmartSnapshot struct {
	Service string                         `json:"service,omitempty"`
	Pin     string                         `json:"pin,omitempty"`
	Probing bool                           `json:"probing,omitempty"`
	Members map[string]SmartMemberSnapshot `json:"members,omitempty"`
}

type smartPriorityRule struct {
	pattern *regexp2.Regexp
	factor  float64
}

// proxyHealthSnap holds a lock-free snapshot of a member proxy's URL-test state
// collected before acquiring Smart.mu.
type proxyHealthSnap struct {
	alive bool
	delay uint16
}

func snapshotProxyHealth(proxies []C.Proxy, testUrl string) []proxyHealthSnap {
	snaps := make([]proxyHealthSnap, len(proxies))
	for i, proxy := range proxies {
		if proxy == nil {
			continue
		}
		snaps[i] = proxyHealthSnap{
			alive: proxy.AliveForTestUrl(testUrl),
			delay: proxy.LastDelayForTestUrl(testUrl),
		}
	}
	return snaps
}

// smartPolicyState tracks the observed quality of one member policy.
type smartPolicyState struct {
	score         float64 // EWMA of first-response latency in ms; 0 means unknown
	lastSample    time.Time
	lossPenalty   float64 // EWMA of the retransmission penalty in ms
	lossUpdated   time.Time
	jitterPenalty float64 // EWMA of the kernel TCP RTTVar jitter penalty in ms
	jitterUpdated time.Time
	lastFail      time.Time
	failStreak    int
	usage         float64 // decayed session count, used for Now()
	usageUpdated  time.Time
}

func (st *smartPolicyState) clone() *smartPolicyState {
	if st == nil {
		return nil
	}
	cp := *st
	return &cp
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
		alpha := smartEwmaAlpha
		sample := delayMs
		if !st.lastSample.IsZero() && now.Sub(st.lastSample) > smartScoreHalfLife {
			alpha = smartEwmaStaleAlpha
		}
		// Winsorize extreme one-off spikes (e.g. slow API/LLM TTFB) so a single
		// slow endpoint cannot knock a healthy node out of the preferred band.
		spikeCap := math.Max(st.score*smartSpikeMultiplier, smartSpikeFloor)
		if sample > spikeCap {
			sample = spikeCap
			if alpha > smartEwmaSpikeAlpha {
				alpha = smartEwmaSpikeAlpha
			}
		}
		st.score = st.score*(1-alpha) + sample*alpha
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

func (st *smartPolicyState) inCooldown(now time.Time) bool {
	return st.failStreak > 0 && !st.lastFail.IsZero() && now.Sub(st.lastFail) < st.failCooldown()
}

// observeLoss folds an observed retransmission ratio (0.01 = 1%) into the
// policy's loss penalty, decaying any stale penalty before smoothing so an old
// outage is never resurrected by a clean connection hours later.
func (st *smartPolicyState) observeLoss(ratio float64, now time.Time) {
	penalty := math.Min(ratio*100*smartLossPenaltyPerPct, smartLossPenaltyMax)
	prev := st.decayedLoss(now)
	if prev <= 0 {
		st.lossPenalty = penalty
	} else {
		st.lossPenalty = prev*0.5 + penalty*0.5
	}
	st.lossUpdated = now
}

// observeSocketRTT incorporates transport-level RTT and RTTVar reported by the
// kernel TCP stack (unaffected by target server application think time).
func (st *smartPolicyState) observeSocketRTT(rtt, rttvar time.Duration, now time.Time) {
	if rtt > 0 && st.score <= 0 {
		rttMs := float64(rtt) / float64(time.Millisecond)
		if rttMs >= smartMinScore && rttMs <= smartSampleCap {
			st.score = rttMs
			st.lastSample = now
		}
	}
	if rttvar <= 0 {
		return
	}
	rttvarMs := float64(rttvar) / float64(time.Millisecond)
	penalty := 0.0
	if rttvarMs > smartJitterBaseMs {
		penalty = math.Min((rttvarMs-smartJitterBaseMs)*smartJitterWeight, smartJitterPenaltyMax)
	}
	prev := st.decayedJitter(now)
	if prev <= 0 {
		st.jitterPenalty = penalty
	} else {
		st.jitterPenalty = prev*0.7 + penalty*0.3
	}
	st.jitterUpdated = now
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

func (st *smartPolicyState) decayedJitter(now time.Time) float64 {
	if st.jitterUpdated.IsZero() || st.jitterPenalty <= 0 {
		return st.jitterPenalty
	}
	age := now.Sub(st.jitterUpdated)
	if age <= 0 {
		return st.jitterPenalty
	}
	return st.jitterPenalty * math.Exp2(-age.Seconds()/smartLossHalfLife.Seconds())
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

// penalty is the loss, jitter, and failure penalty in ms. It is added after the
// policy-priority factor has been applied, so a factor below 1 cannot soften
// an observed penalty.
func (st *smartPolicyState) penalty(now time.Time) float64 {
	penalty := st.decayedLoss(now) + st.decayedJitter(now)
	if st.inCooldown(now) {
		penalty += smartFailPenalty * float64(st.failStreak)
	}
	return penalty
}

// effectiveScore is the latency plus penalties, before the policy-priority factor.
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
// connections of one group. Site memory is not part of it: the caller applies
// it from the current record, per destination for a general group and once
// for the whole service group.
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
	interval       time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.RWMutex
	selected      string
	states        map[string]*smartPolicyState
	sites         map[string]*smartSiteRecord
	priority      []smartPriorityRule
	priorityCache map[string]float64
	rankCache     *smartRankCache
	rankGen       uint64
	lastWakeup    time.Time
	pickCounter   atomic.Uint64

	// service is empty unless the group ranks members by their ability to
	// reach one service and, unless pinSite is set, fixes on one member for
	// everything it routes; verdicts holds the last decidable probe result
	// per member, attempts the last probe try, decidable or not.
	service string
	// pinSite (pin: site) reverts a service group to per-site memory and
	// in-band rotation: the sticky pick works per destination instead of
	// fixing the whole group on one member.
	pinSite   bool
	verdicts  map[string]serviceVerdict
	attempts  map[string]serviceProbeAttempt
	lastProbe time.Time
	probing   bool
	// forcePending holds the members a manual re-test asked for while another
	// probe run was in flight, and forcePendingCurrent the member the group was
	// routing through at that moment; the next run picks both up.
	forcePending        map[string]struct{}
	forcePendingCurrent string
}

func (s *Smart) probeContext() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// Close cancels in-flight background service probes when the group is replaced
// during a config reload or shutdown.
func (s *Smart) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.GroupBase != nil {
		return s.GroupBase.Close()
	}
	return nil
}

// ImportStateFrom migrates still-fresh runtime state (verdicts, attempts,
// latency/loss scores, and site memory) from a replaced Smart group with the
// same service configuration so config reloads do not trigger cold-start resets.
func (s *Smart) ImportStateFrom(prev *Smart) {
	if prev == nil || prev == s {
		return
	}
	now := time.Now()
	proxies := s.GetProxies(false)
	memberSet := make(map[string]struct{}, len(proxies))
	for _, proxy := range proxies {
		if proxy != nil {
			memberSet[proxy.Name()] = struct{}{}
		}
	}

	prev.mu.RLock()
	sameService := prev.service == s.service
	copiedStates := make(map[string]*smartPolicyState, len(prev.states))
	for name, st := range prev.states {
		if _, ok := memberSet[name]; !ok {
			continue
		}
		if st != nil {
			copiedStates[name] = st.clone()
		}
	}
	var copiedVerdicts map[string]serviceVerdict
	var copiedAttempts map[string]serviceProbeAttempt
	if sameService && s.service != "" {
		copiedVerdicts = make(map[string]serviceVerdict, len(prev.verdicts))
		for name, verdict := range prev.verdicts {
			if _, ok := memberSet[name]; !ok {
				continue
			}
			if verdict.known && now.Sub(verdict.at) <= serviceVerdictTTL {
				copiedVerdicts[name] = verdict
			}
		}
		copiedAttempts = make(map[string]serviceProbeAttempt, len(prev.attempts))
		for name, attempt := range prev.attempts {
			if _, ok := memberSet[name]; !ok {
				continue
			}
			if now.Sub(attempt.at) < attempt.backoff() {
				copiedAttempts[name] = attempt
			}
		}
	}
	var copiedSites map[string]*smartSiteRecord
	if prev.serviceGroupPin() == s.serviceGroupPin() && sameService {
		copiedSites = make(map[string]*smartSiteRecord, len(prev.sites))
		for key, rec := range prev.sites {
			if rec == nil || now.Sub(rec.updated) > smartSiteMemoryTTL {
				continue
			}
			newRec := &smartSiteRecord{updated: rec.updated, proxies: make(map[string]*smartSiteEntry, len(rec.proxies))}
			for name, entry := range rec.proxies {
				if _, ok := memberSet[name]; !ok || entry == nil {
					continue
				}
				cp := *entry
				newRec.proxies[name] = &cp
			}
			if len(newRec.proxies) > 0 {
				copiedSites[key] = newRec
			}
		}
	}
	prev.mu.RUnlock()

	s.mu.Lock()
	if s.states == nil {
		s.states = make(map[string]*smartPolicyState, len(copiedStates))
	}
	for name, st := range copiedStates {
		s.states[name] = st
	}
	if len(copiedVerdicts) > 0 {
		if s.verdicts == nil {
			s.verdicts = make(map[string]serviceVerdict, len(copiedVerdicts))
		}
		for name, verdict := range copiedVerdicts {
			s.verdicts[name] = verdict
		}
	}
	if len(copiedAttempts) > 0 {
		if s.attempts == nil {
			s.attempts = make(map[string]serviceProbeAttempt, len(copiedAttempts))
		}
		for name, attempt := range copiedAttempts {
			s.attempts[name] = attempt
		}
	}
	if len(copiedSites) > 0 {
		if s.sites == nil {
			s.sites = make(map[string]*smartSiteRecord, len(copiedSites))
		}
		for key, rec := range copiedSites {
			s.sites[key] = rec
		}
	}
	s.invalidateRankCacheLocked()
	s.mu.Unlock()
}

// Now implements ProxyGroup: the pinned policy, else the member a service
// group fixes on, else the most-used policy in the recent period, else the
// best-scored one. Like Surge, the reported selection is not necessarily the
// policy every new connection will use.
func (s *Smart) Now() string {
	proxies := s.GetProxies(false)
	now := time.Now()

	if selected := s.fixedName(); selected != "" {
		for _, proxy := range proxies {
			if proxy.Name() == selected {
				return selected
			}
		}
	}

	if s.serviceGroupPin() {
		if item := s.servicePick(proxies, now); item != nil {
			return item.proxy.Name()
		}
	}

	snaps := snapshotProxyHealth(proxies, s.testUrl)

	s.mu.RLock()
	defer s.mu.RUnlock()
	bestName := ""
	bestUsage := 0.0
	bestScoreName := ""
	bestScore := math.MaxFloat64
	blockedScoreName := ""
	blockedScore := math.MaxFloat64
	for i, proxy := range proxies {
		if proxy == nil {
			continue
		}
		name := proxy.Name()
		st := s.states[name]
		if st != nil {
			if usage := st.decayedUsage(now); usage > bestUsage {
				bestUsage = usage
				bestName = name
			}
		}
		score := s.scoreOfSnapLocked(name, snaps[i].delay, st, now)
		if s.serviceUnusableLocked(name, now) {
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
	if bestName != "" && (bestScoreName == "" || !s.serviceUnusableLocked(bestName, now)) {
		return bestName
	}
	if bestScoreName != "" {
		return bestScoreName
	}
	return blockedScoreName
}

// Snapshot returns a read-only view of the group's scoring and service-probe
// state for UI rendering and API diagnostics.
func (s *Smart) Snapshot() SmartSnapshot {
	proxies := s.GetProxies(false)
	now := time.Now()
	ranked := s.rankedCandidates(proxies, now)

	pinMode := "site"
	if s.serviceGroupPin() {
		pinMode = "group"
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	members := make(map[string]SmartMemberSnapshot, len(ranked))
	for _, item := range ranked {
		name := item.proxy.Name()
		st := s.states[name]
		var region string
		if v, ok := s.verdicts[name]; ok && v.known && now.Sub(v.at) <= serviceVerdictTTL {
			region = v.region
		}
		members[name] = SmartMemberSnapshot{
			Score:    int(math.Round(item.score)),
			Verified: item.verified,
			Blocked:  item.blocked,
			Region:   region,
			Cooling:  st != nil && st.inCooldown(now),
		}
	}
	return SmartSnapshot{
		Service: s.service,
		Pin:     pinMode,
		Probing: s.probing,
		Members: members,
	}
}

// servicePick returns the member a service group fixes on next: the newest
// success still inside the preferred band, else the best band member at cold
// start. It shares preferredBandPick with the connection path so the panel,
// Unwrap and the routing agree on one member.
func (s *Smart) servicePick(proxies []C.Proxy, now time.Time) *smartCandidate {
	ranked := s.rankedCandidates(proxies, now)
	if len(ranked) == 0 {
		return nil
	}
	s.mu.RLock()
	var siteProxies map[string]*smartSiteEntry
	if record := s.sites[s.service]; record != nil {
		siteProxies = record.proxies
	}
	pick, ok := preferredBandPickRaw(ranked, siteProxies, now, true, true)
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return &ranked[pick]
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
// Only an explicit caller cancellation (context.Canceled on the parent context)
// or ErrNotSupport absolves the node. A deadline exceeded during a dial—whether
// from the per-attempt sub-timeout or from a black-hole node exhausting the
// tunnel's dial timeout—is a node failure so the node enters cooldown and
// future requests switch away.
func smartDialFailure(parentCtx context.Context, err error) bool {
	if err == nil || errors.Is(err, C.ErrNotSupport) {
		return false
	}
	if parentCtx != nil && errors.Is(parentCtx.Err(), context.Canceled) {
		return false
	}
	return true
}

// dialAttemptContext derives a per-attempt sub-timeout from parentCtx so a
// single black-hole candidate cannot consume the entire tunnel dial deadline
// and prevent fallback to remaining candidates.
func dialAttemptContext(parentCtx context.Context, attempt, limit int) (context.Context, context.CancelFunc) {
	deadline, hasDeadline := parentCtx.Deadline()
	if !hasDeadline {
		return parentCtx, func() {}
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || attempt >= limit-1 || remaining <= smartDialMinBudget {
		return parentCtx, func() {}
	}
	var budget time.Duration
	if attempt == 0 {
		budget = remaining * 3 / 5
		if budget > smartDialFirstMaxBudget {
			budget = smartDialFirstMaxBudget
		}
	} else {
		left := limit - attempt
		budget = remaining / time.Duration(left)
	}
	if budget < smartDialMinBudget {
		budget = smartDialMinBudget
	}
	if budget >= remaining {
		return parentCtx, func() {}
	}
	return context.WithTimeout(parentCtx, budget)
}

func (s *Smart) wrapDialedConn(conn C.Conn, proxy C.Proxy, metadata *C.Metadata, dialDone time.Time, dialLatency time.Duration) C.Conn {
	s.reportUsed(proxy.Name())
	conn.AppendToChains(s)

	if N.NeedHandshake(conn) {
		conn = callback.NewFirstWriteCallBackConn(conn, func(err error) {
			if err == nil {
				s.onDialSuccess()
				return
			}
			if smartNodeFailure(err) {
				// EarlyConn handshake failures happen on first write after
				// DialContext already returned; record node failure so tunnel
				// retries immediately pick a different candidate.
				s.reportFailure(proxy.Name(), metadata)
				s.onDialFailed(proxy.Type(), err, s.healthCheck)
			}
		})
	}
	return newSmartConn(conn, s, proxy.Name(), metadata, dialDone, dialLatency)
}

type hedgeResult struct {
	idx     int
	proxy   C.Proxy
	conn    C.Conn
	err     error
	doneAt  time.Time
	latency time.Duration
}

// dialHedged dials candidates[0], and if it stays silent past hedgeDelay,
// concurrently dials candidates[1] so slow or black-holed nodes fail over in
// sub-second time. The loser is canceled and closed if it finishes late.
func (s *Smart) dialHedged(ctx context.Context, metadata *C.Metadata, first, second C.Proxy, hedgeDelay time.Duration) (C.Conn, C.Proxy, error, bool) {
	attemptCtx1, cancel1 := dialAttemptContext(ctx, 0, smartDialRetryLimit)
	ch := make(chan hedgeResult, 2)

	dialOne := func(idx int, dialCtx context.Context, p C.Proxy) {
		start := time.Now()
		conn, err := p.DialContext(dialCtx, metadata)
		done := time.Now()
		lat := done.Sub(start)
		if lat < 0 {
			lat = 0
		}
		ch <- hedgeResult{idx: idx, proxy: p, conn: conn, err: err, doneAt: done, latency: lat}
	}

	go dialOne(0, attemptCtx1, first)

	timer := time.NewTimer(hedgeDelay)
	defer timer.Stop()

	var cancel2 context.CancelFunc
	hedged := false

	select {
	case res := <-ch:
		cancel1()
		if res.err == nil {
			return s.wrapDialedConn(res.conn, res.proxy, metadata, res.doneAt, res.latency), res.proxy, nil, false
		}
		if smartDialFailure(ctx, res.err) {
			s.reportFailure(res.proxy.Name(), metadata)
		}
		return nil, res.proxy, res.err, false
	case <-timer.C:
		if ctx.Err() != nil {
			cancel1()
			return nil, first, ctx.Err(), false
		}
		hedged = true
		var attemptCtx2 context.Context
		attemptCtx2, cancel2 = dialAttemptContext(ctx, 1, smartDialRetryLimit)
		go dialOne(1, attemptCtx2, second)
	case <-ctx.Done():
		cancel1()
		return nil, first, ctx.Err(), false
	}

	defer func() {
		cancel1()
		if cancel2 != nil {
			cancel2()
		}
	}()

	var lastErr error
	var lastProxy C.Proxy
	for completed := 0; completed < 2; completed++ {
		res := <-ch
		if res.err == nil {
			// Cancel the slower branch and drain/close its connection if it arrives.
			if res.idx == 0 && cancel2 != nil {
				cancel2()
			} else if res.idx == 1 {
				cancel1()
			}
			if completed == 0 {
				go func() {
					other := <-ch
					if other.conn != nil {
						_ = other.conn.Close()
					}
					// If the primary timed out / errored while the hedge won,
					// do not penalize a mere cancellation caused by winning.
				}()
			}
			return s.wrapDialedConn(res.conn, res.proxy, metadata, res.doneAt, res.latency), res.proxy, nil, hedged
		}
		lastErr = res.err
		lastProxy = res.proxy
		if smartDialFailure(ctx, res.err) {
			s.reportFailure(res.proxy.Name(), metadata)
		}
	}
	return nil, lastProxy, lastErr, hedged
}

// DialContext implements C.ProxyAdapter
func (s *Smart) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	candidates, canHedge, firstScore := s.selectDialCandidates(metadata, true, false)

	var lastErr error
	var lastProxy C.Proxy
	attempts := 0

	if canHedge && len(candidates) >= 2 && ctx.Err() == nil {
		hedgeDelay := smartHedgeDelayFn(firstScore)
		conn, proxy, err, hedged := s.dialHedged(ctx, metadata, candidates[0], candidates[1], hedgeDelay)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		lastProxy = proxy
		if hedged {
			attempts = 2
			candidates = candidates[2:]
		} else {
			attempts = 1
			candidates = candidates[1:]
		}
	}

	for _, proxy := range candidates {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}

		attemptCtx, cancel := dialAttemptContext(ctx, attempts, smartDialRetryLimit)
		dialStart := time.Now()
		conn, err := proxy.DialContext(attemptCtx, metadata)
		cancel()
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
			log.Debugln("[Smart] %s dial via %s failed: %v, fallback to next candidate", s.Name(), proxy.Name(), err)
			continue
		}
		dialDone := time.Now()
		dialLatency := dialDone.Sub(dialStart)
		if dialLatency < 0 {
			dialLatency = 0
		}

		return s.wrapDialedConn(conn, proxy, metadata, dialDone, dialLatency), nil
	}

	if lastErr == nil {
		lastErr = errors.New("smart: no available proxy")
	} else if lastProxy != nil && smartDialFailure(ctx, lastErr) {
		s.onDialFailed(lastProxy.Type(), lastErr, s.healthCheck)
	}
	return nil, lastErr
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Smart) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	candidates, _, _ := s.selectDialCandidates(metadata, true, true)

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

		attemptCtx, cancel := dialAttemptContext(ctx, attempts, smartDialRetryLimit)
		listenStart := time.Now()
		pc, err := proxy.ListenPacketContext(attemptCtx, metadata)
		cancel()
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

		listenDone := time.Now()
		listenLatency := listenDone.Sub(listenStart)
		if listenLatency < 0 {
			listenLatency = 0
		}
		s.reportUsed(proxy.Name())
		pc.AppendToChains(s)
		return newSmartPacketConn(pc, s, proxy.Name(), metadata, listenDone, listenLatency), nil
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
// group: the pinned policy when it is still a member, otherwise for a service
// group the member it fixes on, otherwise the best-scored alive policy,
// otherwise the best-scored policy. Capability queries and Unwrap use it so
// the answer never depends on a random pick.
func (s *Smart) representativeProxy(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := s.GetProxies(touch)
	if len(proxies) == 0 {
		return nil
	}

	now := time.Now()
	ranked := s.rankedCandidates(proxies, now)
	if len(ranked) == 0 {
		return nil
	}

	s.mu.RLock()
	pinned := s.selected
	s.mu.RUnlock()

	if pinned != "" {
		for _, item := range ranked {
			if item.proxy.Name() == pinned {
				return item.proxy
			}
		}
	}
	if s.serviceGroupPin() {
		if item := s.servicePick(proxies, now); item != nil {
			return item.proxy
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
	emptyFallbackName := ""
	if ef := s.EmptyFallback(); ef != nil {
		emptyFallbackName = ef.Name()
	}
	snap := s.Snapshot()
	payload := map[string]any{
		"type":           s.Type().String(),
		"now":            s.Now(),
		"all":            all,
		"testUrl":        s.testUrl,
		"expectedStatus": s.expectedStatus,
		"fixed":          s.fixedName(),
		"hidden":         s.Hidden(),
		"icon":           s.Icon(),
		"emptyFallback":  emptyFallbackName,
		"smart":          snap,
	}
	return json.Marshal(payload)
}

func (s *Smart) fixedName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
	proxies := s.GetProxies(false)
	snaps := snapshotProxyHealth(proxies, s.testUrl)
	alive := make(map[string]bool, len(proxies))
	current := make(map[string]struct{}, len(proxies))
	for i, proxy := range proxies {
		if proxy == nil {
			continue
		}
		name := proxy.Name()
		current[name] = struct{}{}
		alive[name] = snaps[i].alive
	}
	s.mu.Lock()
	for name, st := range s.states {
		if _, ok := current[name]; !ok {
			delete(s.states, name)
			continue
		}
		if alive[name] {
			st.failStreak = 0
		}
	}
	for name := range s.priorityCache {
		if _, ok := current[name]; !ok {
			delete(s.priorityCache, name)
		}
	}
	s.invalidateRankCacheLocked()
	s.mu.Unlock()

	s.maybeProbeService(proxies)
}

// maybeWakeupHealthCheck triggers an async URL test when a lazy group wakes up
// without any measured member delays, so cold-start traffic does not stay
// trapped on the first randomly sampled node for up to 10 minutes.
func (s *Smart) maybeWakeupHealthCheck(proxies []C.Proxy, snaps []proxyHealthSnap, now time.Time) {
	if len(proxies) == 0 || len(s.providers) == 0 {
		return
	}
	hasMeasured := false
	for _, snap := range snaps {
		if snap.delay != 0 && snap.delay != 0xffff {
			hasMeasured = true
			break
		}
	}
	if hasMeasured {
		return
	}
	s.mu.Lock()
	if !s.lastWakeup.IsZero() && now.Sub(s.lastWakeup) < smartWakeupCooldown {
		s.mu.Unlock()
		return
	}
	s.lastWakeup = now
	s.mu.Unlock()

	go s.healthCheck()
}

type smartCandidate struct {
	proxy    C.Proxy
	score    float64
	alive    bool
	blocked  bool // probe verdict or repeated failures say this member cannot serve the service
	verified bool // a decidable probe confirmed this member can serve the service
}

// siteStatus classifies a policy for one destination using a snapshot of the
// group's site memory. A hit widens the preferred gap, a miss keeps the policy
// out of the first pick.
func siteStatus(entries map[string]smartSiteEntry, name string, now time.Time) (hit, miss bool) {
	if entries == nil {
		return false, false
	}
	entry, ok := entries[name]
	if !ok {
		return false, false
	}
	return siteEntryStatus(entry, now)
}

func siteStatusRaw(entries map[string]*smartSiteEntry, name string, now time.Time) (hit, miss bool) {
	if entries == nil {
		return false, false
	}
	entry, ok := entries[name]
	if !ok || entry == nil {
		return false, false
	}
	return siteEntryStatus(*entry, now)
}

func siteEntryStatus(entry smartSiteEntry, now time.Time) (hit, miss bool) {
	successFresh := !entry.lastSuccess.IsZero() && now.Sub(entry.lastSuccess) < smartSiteMemoryTTL
	failureFresh := !entry.lastFailure.IsZero() && now.Sub(entry.lastFailure) < smartSiteFailureTTL
	hit = successFresh && (!failureFresh || entry.lastSuccess.After(entry.lastFailure))
	miss = failureFresh && !hit
	return hit, miss
}

// stickySitePick returns the preferred member with the newest success in the
// group's memory record.
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

func stickySitePickRaw(ranked []smartCandidate, preferred []int, entries map[string]*smartSiteEntry, now time.Time) (int, bool) {
	sticky := -1
	var newest time.Time
	for _, idx := range preferred {
		name := ranked[idx].proxy.Name()
		if hit, _ := siteStatusRaw(entries, name, now); !hit {
			continue
		}
		if success := entries[name].lastSuccess; sticky < 0 || success.After(newest) {
			sticky, newest = idx, success
		}
	}
	return sticky, sticky >= 0
}

// preferredBandPick returns the first choice among the policies inside the
// preferred band around the best usable score. Kept with value-map signature
// for direct unit tests.
func preferredBandPick(ranked []smartCandidate, entries map[string]smartSiteEntry, now time.Time, sticky, deterministic bool) (int, bool) {
	var raw map[string]*smartSiteEntry
	if len(entries) > 0 {
		raw = make(map[string]*smartSiteEntry, len(entries))
		for k, v := range entries {
			entry := v
			raw[k] = &entry
		}
	}
	return preferredBandPickRaw(ranked, raw, now, sticky, deterministic)
}

// preferredBandPickRaw performs band selection directly over the group's site
// map under RLock without allocating a copied map per connection.
func preferredBandPickRaw(ranked []smartCandidate, entries map[string]*smartSiteEntry, now time.Time, sticky, deterministic bool) (int, bool) {
	verifiedUsable := false
	for _, item := range ranked {
		if !item.alive || item.blocked || !item.verified {
			continue
		}
		if _, miss := siteStatusRaw(entries, item.proxy.Name(), now); miss {
			continue
		}
		verifiedUsable = true
		break
	}
	usable := func(item smartCandidate) bool {
		if !item.alive || item.blocked {
			return false
		}
		if verifiedUsable && !item.verified {
			return false
		}
		_, miss := siteStatusRaw(entries, item.proxy.Name(), now)
		return !miss
	}

	best := 0.0
	hasBest := false
	for _, item := range ranked {
		if !usable(item) {
			continue
		}
		best = item.score
		hasBest = true
		break
	}
	if !hasBest {
		return -1, false
	}

	baseGap := math.Max(best*smartPreferredGapRatio, smartPreferredGapMin)
	var preferredStack [16]int
	preferred := preferredStack[:0]
	for i, item := range ranked {
		if !usable(item) {
			continue
		}
		hit, _ := siteStatusRaw(entries, item.proxy.Name(), now)
		gap := baseGap
		if hit {
			gap = math.Max(best*smartSitePreferredGap, smartPreferredGapMin)
		}
		if item.score <= best+gap {
			preferred = append(preferred, i)
		}
	}
	if len(preferred) == 0 {
		return -1, false
	}
	if sticky {
		if member, ok := stickySitePickRaw(ranked, preferred, entries, now); ok {
			return member, true
		}
	}
	if deterministic {
		return preferred[0], true
	}
	return preferred[rand.Intn(len(preferred))], true
}

// sameProxyList reports whether both slices share a backing array. GroupBase
// rebuilds its proxy slice when a provider version changes, so backing-array
// identity notices membership updates without comparing every element.
func sameProxyList(a, b []C.Proxy) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// rankedCandidates returns the group's members ordered by score. The result is
// cached for smartRankCacheTTL and shared between connections; callers must
// treat it as read-only.
func (s *Smart) rankedCandidates(proxies []C.Proxy, now time.Time) []smartCandidate {
	s.mu.RLock()
	if cache := s.rankCache; cache != nil &&
		cache.gen == s.rankGen &&
		now.Sub(cache.builtAt) < smartRankCacheTTL &&
		sameProxyList(cache.proxies, proxies) {
		ranked := cache.ranked
		s.mu.RUnlock()
		return ranked
	}
	gen := s.rankGen
	s.mu.RUnlock()

	// Snapshot each proxy's health outside s.mu to maintain lock ordering.
	snaps := snapshotProxyHealth(proxies, s.testUrl)
	s.maybeWakeupHealthCheck(proxies, snaps, now)

	// Precompute priority factors if any rules exist and cache misses occur.
	var factors []float64
	if len(s.priority) > 0 {
		factors = s.resolvePriorityFactors(proxies)
	}

	s.mu.RLock()
	candidates := make([]smartCandidate, 0, len(proxies))
	for i, proxy := range proxies {
		if proxy == nil {
			continue
		}
		name := proxy.Name()
		st := s.states[name]
		factor := 1.0
		if factors != nil {
			factor = factors[i]
		}
		fallback := smartUnknownScore
		if snaps[i].delay != 0xffff && snaps[i].delay > 0 {
			fallback = float64(snaps[i].delay)
		}
		score := fallback * factor
		if st != nil {
			score = st.scored(fallback, factor, now)
		}
		candidates = append(candidates, smartCandidate{
			proxy:    proxy,
			score:    score,
			alive:    snaps[i].alive,
			blocked:  s.serviceUnusableLocked(name, now),
			verified: s.serviceVerifiedLocked(name, now),
		})
	}
	s.mu.RUnlock()

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].score < candidates[j].score
	})

	s.mu.Lock()
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

// resolvePriorityFactors returns the priority factor for each proxy, caching
// regex evaluations in s.priorityCache so regexp2 does not run on every cache rebuild.
func (s *Smart) resolvePriorityFactors(proxies []C.Proxy) []float64 {
	factors := make([]float64, len(proxies))
	var missingIdx []int

	s.mu.RLock()
	for i, proxy := range proxies {
		if proxy == nil {
			factors[i] = 1.0
			continue
		}
		if f, ok := s.priorityCache[proxy.Name()]; ok {
			factors[i] = f
		} else {
			missingIdx = append(missingIdx, i)
		}
	}
	s.mu.RUnlock()

	if len(missingIdx) == 0 {
		return factors
	}
	for _, idx := range missingIdx {
		factors[idx] = s.priorityFactor(proxies[idx].Name())
	}
	s.mu.Lock()
	if s.priorityCache == nil {
		s.priorityCache = make(map[string]float64, len(proxies))
	}
	for _, idx := range missingIdx {
		s.priorityCache[proxies[idx].Name()] = factors[idx]
	}
	s.mu.Unlock()
	return factors
}

// pickFirstIndexLocked resolves the first candidate index using the group's
// pinned member, site memory, and preferred band. Callers must hold s.mu.RLock.
func (s *Smart) pickFirstIndexLocked(ranked []smartCandidate, siteKey string, now time.Time, allowExplore bool) (int, bool) {
	var siteProxies map[string]*smartSiteEntry
	if siteKey != "" {
		if record := s.sites[siteKey]; record != nil {
			siteProxies = record.proxies
		}
	}

	if s.selected != "" {
		for i, item := range ranked {
			if item.proxy.Name() == s.selected {
				return i, true
			}
		}
	}

	// Controlled exploration for general groups: every smartExploreEvery picks,
	// give a near-band or unsampled alive member a chance to prove it recovered.
	if allowExplore && s.service == "" && len(ranked) > 1 && s.pickCounter.Add(1)%smartExploreEvery == 0 {
		if idx, ok := s.exploreCandidateLocked(ranked, siteProxies, now); ok {
			return idx, false
		}
	}

	if pick, ok := preferredBandPickRaw(ranked, siteProxies, now, s.service != "", s.serviceGroupPin()); ok {
		return pick, false
	}

	// Fallback when every live member has a site miss: prefer healthy live over blocked over dead.
	for i, item := range ranked {
		if item.alive && !item.blocked {
			return i, false
		}
	}
	for i, item := range ranked {
		if item.alive {
			return i, false
		}
	}
	return 0, false
}

// exploreCandidateLocked selects an unsampled or near-top alive member outside
// the immediate winner so general groups can rediscover improved nodes without
// waiting for a full 10-minute decay cycle. Callers must hold s.mu.RLock.
func (s *Smart) exploreCandidateLocked(ranked []smartCandidate, siteProxies map[string]*smartSiteEntry, now time.Time) (int, bool) {
	limit := len(ranked)
	if limit > 8 {
		limit = 8
	}
	var pool [8]int
	n := 0
	for i := 1; i < limit; i++ {
		item := ranked[i]
		if !item.alive || item.blocked {
			continue
		}
		if _, miss := siteStatusRaw(siteProxies, item.proxy.Name(), now); miss {
			continue
		}
		st := s.states[item.proxy.Name()]
		if st != nil && st.inCooldown(now) {
			continue
		}
		pool[n] = i
		n++
	}
	if n == 0 {
		return -1, false
	}
	return pool[rand.Intn(n)], true
}

// selectDialCandidates picks at most smartDialRetryLimit candidates on the hot
// path (or all UDP-capable candidates up to the retry limit) without building
// an O(N) slice on large rosters.
func (s *Smart) selectDialCandidates(metadata *C.Metadata, touch, requireUDP bool) (candidates []C.Proxy, canHedge bool, firstScore float64) {
	proxies := s.GetProxies(touch)
	if len(proxies) == 0 {
		return nil, false, 0
	}
	s.maybeProbeService(proxies)

	now := time.Now()
	ranked := s.rankedCandidates(proxies, now)
	if len(ranked) == 0 {
		return nil, false, 0
	}
	siteKey := s.memoryKey(metadata)

	s.mu.RLock()
	firstPick, isPinned := s.pickFirstIndexLocked(ranked, siteKey, now, !requireUDP)
	var hit, miss bool
	if siteKey != "" && firstPick >= 0 {
		if record := s.sites[siteKey]; record != nil {
			hit, miss = siteStatusRaw(record.proxies, ranked[firstPick].proxy.Name(), now)
		}
	}
	s.mu.RUnlock()

	order := make([]C.Proxy, 0, smartDialRetryLimit)
	var secondHealthy bool
	addIfEligible := func(idx int) bool {
		p := ranked[idx].proxy
		if requireUDP && !p.SupportUDP() {
			return false
		}
		if len(order) == 1 && ranked[idx].alive && !ranked[idx].blocked {
			secondHealthy = true
		}
		order = append(order, p)
		return len(order) >= smartDialRetryLimit
	}

	if firstPick >= 0 {
		first := ranked[firstPick]
		firstScore = first.score
		log.Debugln("[Smart] %s picked %s (score %.1fms, siteHit=%t, siteMiss=%t, verified=%t, site=%q)",
			s.Name(), first.proxy.Name(), first.score, hit, miss, first.verified, siteKey)
		if addIfEligible(firstPick) {
			return order, false, firstScore
		}
	}

	for i, item := range ranked {
		if i == firstPick || !item.alive || item.blocked || !item.verified {
			continue
		}
		if addIfEligible(i) {
			break
		}
	}
	if len(order) < smartDialRetryLimit {
		for i, item := range ranked {
			if i == firstPick || !item.alive || item.blocked || item.verified {
				continue
			}
			if addIfEligible(i) {
				break
			}
		}
	}
	if len(order) < smartDialRetryLimit {
		for i, item := range ranked {
			if i == firstPick || !item.alive || !item.blocked {
				continue
			}
			if addIfEligible(i) {
				break
			}
		}
	}
	if len(order) < smartDialRetryLimit {
		for i, item := range ranked {
			if i == firstPick || item.alive {
				continue
			}
			if addIfEligible(i) {
				break
			}
		}
	}

	// Only hedge on non-pinned, non-service-group-pin TCP dials when the second
	// candidate is healthy so service groups preserve strict single-IP affinity.
	canHedge = !requireUDP && !isPinned && !s.serviceGroupPin() && len(order) >= 2 && secondHealthy
	return order, canHedge, firstScore
}

// orderedCandidates returns the full ordered list of policies to try for one
// request (preferred pick first, then remaining healthy verified, unverified,
// blocked, and dead policies). Kept for full-order callers and unit tests.
func (s *Smart) orderedCandidates(metadata *C.Metadata, touch bool) []C.Proxy {
	proxies := s.GetProxies(touch)
	if len(proxies) == 0 {
		return nil
	}
	s.maybeProbeService(proxies)

	now := time.Now()
	ranked := s.rankedCandidates(proxies, now)
	if len(ranked) == 0 {
		return nil
	}
	siteKey := s.memoryKey(metadata)

	s.mu.RLock()
	firstPick, _ := s.pickFirstIndexLocked(ranked, siteKey, now, false)
	var hit, miss bool
	if siteKey != "" && firstPick >= 0 {
		if record := s.sites[siteKey]; record != nil {
			hit, miss = siteStatusRaw(record.proxies, ranked[firstPick].proxy.Name(), now)
		}
	}
	s.mu.RUnlock()

	order := make([]C.Proxy, 0, len(ranked))
	if firstPick >= 0 {
		first := ranked[firstPick]
		order = append(order, first.proxy)
		log.Debugln("[Smart] %s picked %s (score %.1fms, siteHit=%t, siteMiss=%t, verified=%t, site=%q)",
			s.Name(), first.proxy.Name(), first.score, hit, miss, first.verified, siteKey)
	}

	for i, item := range ranked {
		if i == firstPick || !item.alive || item.blocked || !item.verified {
			continue
		}
		order = append(order, item.proxy)
	}
	for i, item := range ranked {
		if i == firstPick || !item.alive || item.blocked || item.verified {
			continue
		}
		order = append(order, item.proxy)
	}
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

// scoreOfSnapLocked scores one member using a pre-fetched delay snapshot.
// Callers must hold s.mu (read or write).
func (s *Smart) scoreOfSnapLocked(name string, delay uint16, st *smartPolicyState, now time.Time) float64 {
	fallback := smartUnknownScore
	if delay != 0xffff && delay > 0 {
		fallback = float64(delay)
	}
	factor := 1.0
	if len(s.priority) > 0 {
		if cached, ok := s.priorityCache[name]; ok {
			factor = cached
		} else {
			factor = s.priorityFactor(name)
		}
	}
	if st == nil {
		return fallback * factor
	}
	return st.scored(fallback, factor, now)
}

// scoreOf combines the policy's EWMA latency (seeded by URL test results) with
// its loss and failure penalties.
func (s *Smart) scoreOf(proxy C.Proxy, st *smartPolicyState, now time.Time) float64 {
	return s.scoreOfSnapLocked(proxy.Name(), proxy.LastDelayForTestUrl(s.testUrl), st, now)
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
	if s.states == nil {
		s.states = make(map[string]*smartPolicyState)
	}
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
	// A response slower than smartSampleCap (e.g. LLM thinking / long-poll) is
	// more likely target server think time than node latency: keep site success
	// but do not pollute the latency score.
	if delayMs <= smartSampleCap {
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
	notifySmartSelectionChanged()
}

// invalidateRankCacheLocked forces the next connection to rebuild the ranking;
// the caller must hold s.mu (write lock).
func (s *Smart) invalidateRankCacheLocked() {
	s.rankGen++
	s.rankCache = nil
}

func (s *Smart) reportRetransmit(name string, delta sockstat.TCPStats, baseOK bool) {
	if !baseOK {
		return
	}
	now := time.Now()
	ratio, hasLoss := delta.RetransmitRatio()
	hasRTT := delta.RTT > 0 || delta.RTTVar > 0
	if !hasLoss && !hasRTT {
		return
	}
	s.mu.Lock()
	st := s.stateOf(name)
	if hasLoss {
		st.observeLoss(ratio, now)
	}
	if hasRTT {
		st.observeSocketRTT(delta.RTT, delta.RTTVar, now)
	}
	s.mu.Unlock()
}

func (s *Smart) reportUsed(name string) {
	now := time.Now()
	s.mu.Lock()
	s.stateOf(name).bumpUsage(now)
	s.mu.Unlock()
}

// serviceGroupPin reports whether the group fixes on one member for
// everything it routes: any service group unless pin: site reverts it to
// per-site memory.
func (s *Smart) serviceGroupPin() bool {
	return s.service != "" && !s.pinSite
}

// memoryKey is the key a connection's outcome records under. A group pin
// keeps one record for the whole service group, so the member that served
// any domain is pinned for them all; every other group remembers per
// destination site.
func (s *Smart) memoryKey(metadata *C.Metadata) string {
	if s.serviceGroupPin() {
		return s.service
	}
	return getKey(metadata)
}

// rememberSite records the outcome that drives the group's site memory; the
// caller must hold s.mu (write lock).
func (s *Smart) rememberSite(metadata *C.Metadata, name string, success bool, now time.Time) {
	key := s.memoryKey(metadata)
	if key == "" || name == "" {
		return
	}
	if s.sites == nil {
		s.sites = make(map[string]*smartSiteRecord)
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
// entries, and records that became empty; the caller must hold s.mu (write lock).
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
// new site; the caller must hold s.mu (write lock).
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
// was written and went unanswered, and the socket's retransmission/RTT counters
// when it closes. Once first write and first read complete, ReaderReplaceable
// and WriterReplaceable let sing's bufio.Copy bypass this wrapper completely.
type smartConn struct {
	C.Conn

	smart       *Smart
	proxyName   string
	metadata    *C.Metadata
	dialDone    time.Time     // dial completion, the earliest point latency can start
	dialLatency time.Duration // time spent in proxy.DialContext

	firstWriteNano atomic.Int64 // UnixNano recorded right before the first outbound write
	wroteData      atomic.Bool

	sampler *sockstat.Sampler
	base    sockstat.TCPStats
	baseOK  bool

	firstByteOnce sync.Once
	gotData       atomic.Bool
	readErr       atomic.Bool
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
	if sampler, ok := sockstat.Bind(conn); ok {
		sc.sampler = sampler
		sc.base, sc.baseOK = sampler.Sample()
	}
	return sc
}

func (c *smartConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		if !c.gotData.Load() {
			c.markFirstByte()
		}
	} else if err != nil && !errors.Is(err, io.EOF) {
		c.readErr.Store(true)
	}
	return n, err
}

func (c *smartConn) ReadBuffer(buffer *buf.Buffer) error {
	err := c.Conn.ReadBuffer(buffer)
	if buffer.Len() > 0 {
		if !c.gotData.Load() {
			c.markFirstByte()
		}
	} else if err != nil && !errors.Is(err, io.EOF) {
		c.readErr.Store(true)
	}
	return err
}

func (c *smartConn) Write(b []byte) (int, error) {
	if c.wroteData.Load() {
		return c.Conn.Write(b)
	}
	// Capture timestamp before the first write so EarlyConn handshake duration
	// is included in first-response latency.
	startNano := time.Now().UnixNano()
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.firstWriteNano.CompareAndSwap(0, startNano)
		c.wroteData.Store(true)
	}
	return n, err
}

func (c *smartConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.wroteData.Load() {
		return c.Conn.WriteBuffer(buffer)
	}
	size := buffer.Len()
	startNano := time.Now().UnixNano()
	err := c.Conn.WriteBuffer(buffer)
	if err == nil && size > 0 {
		c.firstWriteNano.CompareAndSwap(0, startNano)
		c.wroteData.Store(true)
	}
	return err
}

func (c *smartConn) Close() error {
	c.closeOnce.Do(func() {
		// Skip socket sampling on multiplexed/UDP transports where Bind failed.
		if c.baseOK && c.sampler != nil {
			if stats, ok := c.sampler.Sample(); ok {
				c.smart.reportRetransmit(c.proxyName, stats.Sub(c.base), true)
			}
		}
		if c.wroteData.Load() && !c.gotData.Load() {
			if c.shouldReportUnanswered() {
				c.smart.reportFailure(c.proxyName, c.metadata)
			}
		}
	})
	return c.Conn.Close()
}

func (c *smartConn) shouldReportUnanswered() bool {
	if c.readErr.Load() {
		return true
	}
	minWait := smartUnansweredMinWait
	if minWait <= 0 {
		return true
	}
	firstNano := c.firstWriteNano.Load()
	if firstNano <= 0 {
		return false
	}
	return time.Since(time.Unix(0, firstNano)) >= minWait
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
		base := c.dialDone
		if firstNano := c.firstWriteNano.Load(); firstNano > 0 {
			firstWrite := time.Unix(0, firstNano)
			if firstWrite.After(base) {
				base = firstWrite
			}
		}
		delayMs := float64(firstResponseDelay(base, time.Now(), c.dialLatency)) / float64(time.Millisecond)
		c.smart.reportLatency(c.proxyName, c.metadata, delayMs)
	})
}

func (c *smartConn) Upstream() any {
	return c.Conn
}

func (c *smartConn) ReaderReplaceable() bool {
	return c.gotData.Load()
}

func (c *smartConn) WriterReplaceable() bool {
	return c.wroteData.Load()
}

var _ C.Conn = (*smartConn)(nil)
var _ N.ExtendedConn = (*smartConn)(nil)

// smartPacketConn wraps a member packet connection the way smartConn wraps a
// TCP one: the first answered datagram feeds the latency scorer and the site
// memory, and a session that wrote and went unanswered counts as a node
// failure. Retransmission counters are TCP-only and have no UDP equivalent.
type smartPacketConn struct {
	C.PacketConn

	smart     *Smart
	proxyName string
	metadata  *C.Metadata

	listenDone    time.Time     // listen completion, the earliest point latency can start
	listenLatency time.Duration // time spent in proxy.ListenPacketContext

	firstWriteNano atomic.Int64
	wroteData      atomic.Bool

	firstReadOnce sync.Once
	gotData       atomic.Bool
	readErr       atomic.Bool
	closeOnce     sync.Once
}

func newSmartPacketConn(pc C.PacketConn, smart *Smart, proxyName string, metadata *C.Metadata, listenDone time.Time, listenLatency time.Duration) C.PacketConn {
	return &smartPacketConn{
		PacketConn:    pc,
		smart:         smart,
		proxyName:     proxyName,
		metadata:      metadata,
		listenDone:    listenDone,
		listenLatency: listenLatency,
	}
}

func (c *smartPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if n > 0 {
		if !c.gotData.Load() {
			c.markFirstRead()
		}
	} else if err != nil && !errors.Is(err, io.EOF) {
		c.readErr.Store(true)
	}
	return n, addr, err
}

func (c *smartPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	data, put, addr, err := c.PacketConn.WaitReadFrom()
	if len(data) > 0 {
		if !c.gotData.Load() {
			c.markFirstRead()
		}
	} else if err != nil && !errors.Is(err, io.EOF) {
		c.readErr.Store(true)
	}
	return data, put, addr, err
}

func (c *smartPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.wroteData.Load() {
		return c.PacketConn.WriteTo(b, addr)
	}
	startNano := time.Now().UnixNano()
	n, err := c.PacketConn.WriteTo(b, addr)
	if n > 0 {
		c.firstWriteNano.CompareAndSwap(0, startNano)
		c.wroteData.Store(true)
	}
	return n, err
}

func (c *smartPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.wroteData.Load() && !c.gotData.Load() {
			if c.shouldReportUnanswered() {
				c.smart.reportFailure(c.proxyName, c.metadata)
			}
		}
	})
	return c.PacketConn.Close()
}

func (c *smartPacketConn) shouldReportUnanswered() bool {
	if c.readErr.Load() {
		return true
	}
	minWait := smartUnansweredMinWait
	if minWait <= 0 {
		return true
	}
	firstNano := c.firstWriteNano.Load()
	if firstNano <= 0 {
		return false
	}
	return time.Since(time.Unix(0, firstNano)) >= minWait
}

func (c *smartPacketConn) markFirstRead() {
	c.firstReadOnce.Do(func() {
		c.gotData.Store(true)
		base := c.listenDone
		if firstNano := c.firstWriteNano.Load(); firstNano > 0 {
			firstWrite := time.Unix(0, firstNano)
			if firstWrite.After(base) {
				base = firstWrite
			}
		}
		delayMs := float64(firstResponseDelay(base, time.Now(), c.listenLatency)) / float64(time.Millisecond)
		c.smart.reportLatency(c.proxyName, c.metadata, delayMs)
	})
}

func (c *smartPacketConn) Upstream() any {
	return c.PacketConn
}

var _ C.PacketConn = (*smartPacketConn)(nil)

// normalizePinMode maps the configured pin value onto its struct form. A
// typo must degrade to the default instead of breaking the config, matching
// how an unknown service behaves.
func normalizePinMode(value string) (pinSite bool, err error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "group":
		return false, nil
	case "site":
		return true, nil
	default:
		return false, fmt.Errorf("unknown pin %q, want \"group\" or \"site\"", value)
	}
}

func NewSmart(option GroupCommonOption, smartOption SmartOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (*Smart, error) {
	priority, err := parsePolicyPriority(smartOption.PolicyPriority)
	if err != nil {
		return nil, err
	}
	service, err := normalizeServiceName(smartOption.Service)
	if err != nil {
		log.Warnln("[Smart] %s: %v, service ranking disabled", option.Name, err)
		service = ""
	}
	pinSite, err := normalizePinMode(smartOption.Pin)
	if err != nil {
		log.Warnln("[Smart] %s: %v, pin stays on the group", option.Name, err)
		pinSite = false
	}
	interval := time.Duration(option.Interval) * time.Second
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Smart{
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
		interval:       interval,
		ctx:            ctx,
		cancel:         cancel,
		states:         make(map[string]*smartPolicyState),
		sites:          make(map[string]*smartSiteRecord),
		priority:       priority,
		priorityCache:  make(map[string]float64),
		service:        service,
		pinSite:        pinSite,
		verdicts:       make(map[string]serviceVerdict),
		attempts:       make(map[string]serviceProbeAttempt),
	}
	if service != "" {
		s.loadPersistedVerdicts(time.Now())
	}
	return s, nil
}
