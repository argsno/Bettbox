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
	smartPreferredGapRatio  = 0.15    // preferred set: scores within max(15%, 20ms) of the best
	smartPreferredGapMin    = 20.0    // ms
	smartSitePreferredGap   = 0.4     // widened gap for policies that recently worked for the site
	smartFailCooldown       = time.Minute
	smartFailPenalty        = 600.0 // ms added while a policy is in failure cooldown
	smartLossPenaltyPerPct  = 50.0  // ~50ms per 1% retransmission, like Surge
	smartLossPenaltyMax     = 2000.0
	smartUsageHalfLife      = 10 * time.Minute
	smartSiteMemoryTTL      = time.Hour
	smartSiteMemoryMaxSites = 512
	smartDialRetryLimit     = 3
)

type SmartOption struct {
	PolicyPriority string `group:"policy-priority,omitempty"`
}

type smartPriorityRule struct {
	pattern *regexp2.Regexp
	factor  float64
}

// smartPolicyState tracks the observed quality of one member policy.
type smartPolicyState struct {
	score        float64 // EWMA of first-response latency in ms; 0 means unknown
	lossPenalty  float64 // EWMA of the retransmission penalty in ms
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
	st.failStreak = 0
}

// observeFailure sharply worsens the policy: while the cooldown lasts it is
// ranked below healthy members, and it recovers through later tests or traffic.
func (st *smartPolicyState) observeFailure(now time.Time) {
	st.failStreak++
	st.lastFail = now
}

// observeLoss folds an observed retransmission ratio (0.01 = 1%) into the
// policy's loss penalty.
func (st *smartPolicyState) observeLoss(ratio float64) {
	penalty := math.Min(ratio*100*smartLossPenaltyPerPct, smartLossPenaltyMax)
	if st.lossPenalty <= 0 {
		st.lossPenalty = penalty
	} else {
		st.lossPenalty = st.lossPenalty*0.5 + penalty*0.5
	}
}

func (st *smartPolicyState) effectiveScore(fallback float64, now time.Time) float64 {
	score := st.score
	if score <= 0 {
		score = fallback
	}
	score += st.lossPenalty
	if st.failStreak > 0 && now.Sub(st.lastFail) < smartFailCooldown {
		score += smartFailPenalty * float64(st.failStreak)
	}
	if score < smartMinScore {
		score = smartMinScore
	}
	return score
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

type Smart struct {
	*GroupBase
	disableUDP     bool
	testUrl        string
	expectedStatus string

	mu       sync.Mutex
	selected string
	states   map[string]*smartPolicyState
	sites    map[string]*smartSiteRecord
	priority []smartPriorityRule
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
	for _, proxy := range proxies {
		name := proxy.Name()
		st := s.states[name]
		if st != nil {
			if usage := st.decayedUsage(now); usage > bestUsage {
				bestUsage = usage
				bestName = name
			}
		}
		if score := s.scoreOf(proxy, st, now); score < bestScore {
			bestScore = score
			bestScoreName = name
		}
	}
	if bestName != "" {
		return bestName
	}
	return bestScoreName
}

// DialContext implements C.ProxyAdapter
func (s *Smart) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	candidates := s.orderedCandidates(metadata, true)

	var lastErr error
	attempts := 0
	for _, proxy := range candidates {
		proxy := proxy
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}

		start := time.Now()
		conn, err := proxy.DialContext(ctx, metadata)
		if err != nil {
			lastErr = err
			attempts++
			s.onDialFailed(proxy.Type(), err, s.healthCheck)
			s.reportFailure(proxy.Name(), metadata)
			if attempts >= smartDialRetryLimit {
				break
			}
			log.Debugln("[Smart] %s dial via %s failed: %v, fallback to next candidate", s.Name(), proxy.Name(), err)
			continue
		}

		s.reportUsed(proxy.Name())
		conn.AppendToChains(s)

		if N.NeedHandshake(conn) {
			conn = callback.NewFirstWriteCallBackConn(conn, func(err error) {
				if err == nil {
					s.onDialSuccess()
				} else {
					s.onDialFailed(proxy.Type(), err, s.healthCheck)
				}
			})
		}

		return newSmartConn(conn, s, proxy.Name(), metadata, start), nil
	}

	if lastErr == nil {
		lastErr = errors.New("smart: no available proxy")
	}
	return nil, lastErr
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Smart) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy := s.Unwrap(metadata, true)
	pc, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		s.onDialFailed(proxy.Type(), err, s.healthCheck)
		s.reportFailure(proxy.Name(), metadata)
		return nil, err
	}
	s.reportUsed(proxy.Name())
	pc.AppendToChains(s)
	return pc, nil
}

// SupportUDP implements C.ProxyAdapter
func (s *Smart) SupportUDP() bool {
	if s.disableUDP {
		return false
	}
	return s.Unwrap(nil, false).SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (s *Smart) IsL3Protocol(metadata *C.Metadata) bool {
	return s.Unwrap(metadata, false).IsL3Protocol(metadata)
}

// Unwrap implements C.ProxyAdapter
func (s *Smart) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	candidates := s.orderedCandidates(metadata, touch)
	if len(candidates) == 0 {
		return s.EmptyFallback()
	}
	return candidates[0]
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
	s.mu.Lock()
	for _, st := range s.states {
		st.failStreak = 0
	}
	s.mu.Unlock()
}

type smartCandidate struct {
	proxy    C.Proxy
	score    float64
	alive    bool
	siteHit  bool
	siteMiss bool
}

// orderedCandidates returns the policies to try for one request: the preferred
// pick first (a random member of the policies closest to the best score, or
// the pinned one), then the remaining healthy policies by score, then the
// failed ones, so a dead connection can fall back to the next candidate.
func (s *Smart) orderedCandidates(metadata *C.Metadata, touch bool) []C.Proxy {
	proxies := s.GetProxies(touch)
	if len(proxies) == 0 {
		return nil
	}

	now := time.Now()
	siteKey := getKey(metadata)

	candidates := make([]smartCandidate, 0, len(proxies))
	s.mu.Lock()
	var siteRecord *smartSiteRecord
	if siteKey != "" {
		siteRecord = s.sites[siteKey]
	}
	pinned := s.selected
	for _, proxy := range proxies {
		st := s.states[proxy.Name()]
		item := smartCandidate{
			proxy: proxy,
			score: s.scoreOf(proxy, st, now),
			alive: proxy.AliveForTestUrl(s.testUrl),
		}
		if siteRecord != nil {
			if entry, ok := siteRecord.proxies[proxy.Name()]; ok {
				successFresh := !entry.lastSuccess.IsZero() && now.Sub(entry.lastSuccess) < smartSiteMemoryTTL
				failureFresh := !entry.lastFailure.IsZero() && now.Sub(entry.lastFailure) < smartSiteMemoryTTL
				item.siteHit = successFresh && (!failureFresh || entry.lastSuccess.After(entry.lastFailure))
				item.siteMiss = failureFresh && !item.siteHit
			}
		}
		candidates = append(candidates, item)
	}
	s.mu.Unlock()

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].score < candidates[j].score
	})

	order := make([]C.Proxy, 0, len(candidates))
	skip := make(map[int]struct{}, 2)

	if pinned != "" {
		for i, item := range candidates {
			if item.proxy.Name() == pinned {
				order = append(order, item.proxy)
				skip[i] = struct{}{}
				break
			}
		}
	}

	if len(order) == 0 {
		best := 0.0
		hasBest := false
		for _, item := range candidates {
			if !item.alive || item.siteMiss {
				continue
			}
			best = item.score
			hasBest = true
			break
		}

		var preferred []int
		if hasBest {
			baseGap := math.Max(best*smartPreferredGapRatio, smartPreferredGapMin)
			for i, item := range candidates {
				if !item.alive || item.siteMiss {
					continue
				}
				gap := baseGap
				if item.siteHit {
					gap = math.Max(best*smartSitePreferredGap, smartPreferredGapMin)
				}
				if item.score <= best+gap {
					preferred = append(preferred, i)
				}
			}
		}

		if len(preferred) > 0 {
			pick := preferred[rand.Intn(len(preferred))]
			order = append(order, candidates[pick].proxy)
			skip[pick] = struct{}{}
		} else {
			// nothing healthy (or everything suspended for this site): fall back to the best score
			order = append(order, candidates[0].proxy)
			skip[0] = struct{}{}
		}
	}

	for i, item := range candidates {
		if _, ok := skip[i]; ok {
			continue
		}
		if item.alive {
			order = append(order, item.proxy)
		}
	}
	for i, item := range candidates {
		if _, ok := skip[i]; ok {
			continue
		}
		if !item.alive {
			order = append(order, item.proxy)
		}
	}
	return order
}

// scoreOf combines the policy's EWMA latency (seeded by URL test results),
// loss penalty and failure penalty, multiplied by the policy-priority factor.
func (s *Smart) scoreOf(proxy C.Proxy, st *smartPolicyState, now time.Time) float64 {
	fallback := smartUnknownScore
	if delay := proxy.LastDelayForTestUrl(s.testUrl); delay != 0xffff && delay > 0 {
		fallback = float64(delay)
	}
	var score float64
	if st == nil {
		score = fallback
	} else {
		score = st.effectiveScore(fallback, now)
	}
	return score * s.priorityFactor(proxy.Name())
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
	if delayMs < smartMinScore || delayMs > smartMaxScore {
		return
	}
	now := time.Now()
	s.mu.Lock()
	s.stateOf(name).observeLatency(delayMs, now)
	s.rememberSite(metadata, name, true, now)
	s.mu.Unlock()
}

func (s *Smart) reportFailure(name string, metadata *C.Metadata) {
	now := time.Now()
	s.mu.Lock()
	s.stateOf(name).observeFailure(now)
	s.rememberSite(metadata, name, false, now)
	s.mu.Unlock()
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
	s.stateOf(name).observeLoss(ratio)
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
			return
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

// pruneSites drops expired records; the caller must hold s.mu.
func (s *Smart) pruneSites(now time.Time) {
	for key, record := range s.sites {
		if now.Sub(record.updated) > smartSiteMemoryTTL {
			delete(s.sites, key)
		}
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
// the first-response latency on the first inbound byte, a failure when the
// connection dies before any data arrives, and the socket's retransmission
// counters when it closes.
type smartConn struct {
	C.Conn

	smart     *Smart
	proxyName string
	metadata  *C.Metadata
	start     time.Time

	base   sockstat.TCPStats
	baseOK bool

	firstByteOnce sync.Once
	gotData       atomic.Bool
	closeOnce     sync.Once
}

func newSmartConn(conn C.Conn, smart *Smart, proxyName string, metadata *C.Metadata, start time.Time) C.Conn {
	sc := &smartConn{
		Conn:      conn,
		smart:     smart,
		proxyName: proxyName,
		metadata:  metadata,
		start:     start,
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

func (c *smartConn) Close() error {
	c.closeOnce.Do(func() {
		// the socket must still be open to read its counters
		if stats, ok := sockstat.Sample(c.Conn); ok {
			c.smart.reportRetransmit(c.proxyName, stats.Sub(c.base), c.baseOK)
		}
		if !c.gotData.Load() {
			c.smart.reportFailure(c.proxyName, c.metadata)
		}
	})
	return c.Conn.Close()
}

func (c *smartConn) markFirstByte() {
	c.firstByteOnce.Do(func() {
		c.gotData.Store(true)
		delayMs := float64(time.Since(c.start)) / float64(time.Millisecond)
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
	}, nil
}
