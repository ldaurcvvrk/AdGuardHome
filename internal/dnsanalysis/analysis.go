// Package dnsanalysis provides enhanced DNS request analysis capabilities for
// the AdGuardHome fork.  It collects detailed per-request data including
// processing timelines, filtering results, upstream performance, and cache
// behavior, and exposes them via REST API endpoints.
//
// The module persists request data to a bbolt database on disk, so that the
// recent history survives restarts.  A bounded in-memory ring buffer is kept
// for fast API responses.
package dnsanalysis

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
	bolt "go.etcd.io/bbolt"
)

// maxBufferedRequests is the maximum number of requests to keep in the ring
// buffer for analysis.
const maxBufferedRequests = 10000

// defaultRetention is the default retention period for request data.
const defaultRetention = 24 * time.Hour

// dbFileName is the name of the bbolt database file inside the data directory.
const dbFileName = "dns_analysis.db"

// requestsBucket is the name of the bbolt bucket storing request records.
const requestsBucket = "requests"

// cleanupEvery is the number of writes after which a retention cleanup pass is
// performed.
const cleanupEvery = 100

// RequestAnalysis is the detailed analysis data for a single DNS request.
type RequestAnalysis struct {
	// ID is a unique identifier for the request.
	ID string `json:"id"`

	// Timestamp is the time at which the request was received.
	Timestamp time.Time `json:"timestamp"`

	// Question contains the DNS question data.
	Question QuestionInfo `json:"question"`

	// ClientIP is the IP address of the client making the request.
	ClientIP string `json:"client_ip"`

	// ClientID is the ClientID from DoH/DoQ/DoT if provided.
	ClientID string `json:"client_id,omitempty"`

	// Protocol is the transport protocol used (udp, tcp, doh, dot, doq).
	Protocol string `json:"protocol"`

	// Timeline contains the processing timeline breakdown.
	Timeline TimelineInfo `json:"timeline"`

	// Filtering contains the filtering result details.
	Filtering FilteringInfo `json:"filtering"`

	// Upstream contains upstream server information.
	Upstream UpstreamInfo `json:"upstream"`

	// Cache contains cache behavior information.
	Cache CacheInfo `json:"cache"`

	// ResponseCode is the DNS response code.
	ResponseCode int `json:"response_code"`

	// ResponseCodeName is the human-readable response code name.
	ResponseCodeName string `json:"response_code_name"`

	// Error is set if the request processing failed.
	Error string `json:"error,omitempty"`
}

// QuestionInfo contains DNS question data.
type QuestionInfo struct {
	// Name is the queried domain name.
	Name string `json:"name"`

	// Type is the DNS record type (A, AAAA, etc.).
	Type string `json:"type"`

	// Class is the DNS class.
	Class string `json:"class"`
}

// TimelineInfo contains the processing timeline breakdown in nanoseconds.
type TimelineInfo struct {
	// TotalDuration is the total processing time.
	TotalDuration int64 `json:"total_duration"`

	// InitialProcessingDuration is the time spent in initial processing.
	InitialProcessingDuration int64 `json:"initial_processing_duration"`

	// FilteringBeforeDuration is the time spent in pre-upstream filtering.
	FilteringBeforeDuration int64 `json:"filtering_before_duration"`

	// UpstreamDuration is the time spent waiting for upstream response.
	UpstreamDuration int64 `json:"upstream_duration"`

	// FilteringAfterDuration is the time spent in post-upstream filtering.
	FilteringAfterDuration int64 `json:"filtering_after_duration"`
}

// FilteringInfo contains filtering result details.
type FilteringInfo struct {
	// Matched indicates whether any filter rule was matched.
	Matched bool `json:"matched"`

	// Reason is the filtering reason code.
	Reason string `json:"reason"`

	// MatchedRules are the texts of matched filter rules.
	MatchedRules []string `json:"matched_rules"`

	// MatchedFilterLists are the names of matched filter lists.
	MatchedFilterLists []string `json:"matched_filter_lists"`

	// ServiceName is the name of the blocked service, if applicable.
	ServiceName string `json:"service_name,omitempty"`

	// BlockedIPv4 is the IPv4 address used for blocking.
	BlockedIPv4 string `json:"blocked_ipv4,omitempty"`

	// BlockedIPv6 is the IPv6 address used for blocking.
	BlockedIPv6 string `json:"blocked_ipv6,omitempty"`

	// CanonName is the CNAME target from rewrite rules.
	CanonName string `json:"cname,omitempty"`

	// BlockingMode is the blocking mode used.
	BlockingMode string `json:"blocking_mode,omitempty"`

	// SafeSearchApplied indicates whether safe search was applied.
	SafeSearchApplied bool `json:"safe_search_applied"`

	// SafeBrowsingHit indicates whether safe browsing blocked the request.
	SafeBrowsingHit bool `json:"safe_browsing_hit"`

	// ParentalHit indicates whether parental control blocked the request.
	ParentalHit bool `json:"parental_hit"`

	// RewritesApplied indicates whether rewrite rules were applied.
	RewritesApplied bool `json:"rewrites_applied"`
}

// UpstreamInfo contains upstream server information.
type UpstreamInfo struct {
	// Address is the upstream server address.
	Address string `json:"address,omitempty"`

	// Duration is the time spent waiting for the upstream response.
	Duration int64 `json:"duration,omitempty"`

	// IsCached indicates whether the response was served from cache.
	IsCached bool `json:"is_cached,omitempty"`
}

// CacheInfo contains cache behavior information.
type CacheInfo struct {
	// Hit indicates whether the request was served from cache.
	Hit bool `json:"hit"`

	// Size is the cache entry size in bytes.
	Size int64 `json:"size,omitempty"`
}

// StatsSummary is the aggregated statistics summary for the analysis period.
type StatsSummary struct {
	// TotalRequests is the total number of requests in the period.
	TotalRequests int64 `json:"total_requests"`

	// ByProtocol maps protocol names to request counts.
	ByProtocol map[string]int64 `json:"by_protocol"`

	// ByRCode maps response codes to request counts.
	ByRCode map[string]int64 `json:"by_rcode"`

	// ByFilterReason maps filter reasons to request counts.
	ByFilterReason map[string]int64 `json:"by_filter_reason"`

	// ByUpstream maps upstream addresses to request counts.
	ByUpstream map[string]int64 `json:"by_upstream"`

	// CacheHitRate is the fraction of requests served from cache (0.0-1.0).
	CacheHitRate float64 `json:"cache_hit_rate"`

	// AvgLatencyNs is the average total processing time in nanoseconds.
	AvgLatencyNs int64 `json:"avg_latency_ns"`

	// AvgUpstreamLatencyNs is the average upstream processing time in ns.
	AvgUpstreamLatencyNs int64 `json:"avg_upstream_latency_ns"`

	// BlockedCount is the number of blocked requests.
	BlockedCount int64 `json:"blocked_count"`

	// ModifiedCount is the number of modified responses.
	ModifiedCount int64 `json:"modified_count"`

	// ErrorCount is the number of requests with errors.
	ErrorCount int64 `json:"error_count"`
}

// Config is the configuration for the DNS analysis module.
type Config struct {
	// Logger is used for logging.  It must not be nil.
	Logger *slog.Logger `yaml:"-"`

	// HTTPReg registers HTTP handlers.  It must not be nil.
	HTTPReg aghhttp.Registrar `yaml:"-"`

	// DataDir is the directory to store the persistent database in.  If it is
	// empty, the module runs in memory-only mode.
	DataDir string `yaml:"-"`

	// Enabled indicates whether DNS analysis is enabled.
	Enabled bool `yaml:"enabled"`

	// Retention is the retention period for request data.
	Retention time.Duration `yaml:"retention"`

	// MaxRequests is the maximum number of requests to buffer.
	MaxRequests int `yaml:"max_requests"`
}

// Analysis is the DNS analysis module.
type Analysis struct {
	// logger is used for logging.
	logger *slog.Logger

	// httpReg registers HTTP handlers.
	httpReg aghhttp.Registrar

	// db is the persistent database.  It is nil in memory-only mode.
	db *bolt.DB

	// dbPath is the path to the database file.
	dbPath string

	// mu protects the fields below.
	mu sync.RWMutex

	// enabled indicates whether analysis is enabled.
	enabled bool

	// retention is the retention period for request data.
	retention time.Duration

	// maxRequests is the maximum number of requests to buffer.
	maxRequests int

	// requests is the ring buffer of recent requests.
	requests []*RequestAnalysis

	// nextIdx is the next write index in the ring buffer.
	nextIdx int

	// writeCount counts writes since the last cleanup pass.
	writeCount int

	// stats is the aggregated statistics.
	stats StatsSummary

	// statsSince is the start time of the current stats period.
	statsSince time.Time
}

// New creates a new DNS analysis module.  c must not be nil.
func New(c *Config) (a *Analysis, err error) {
	if c.Logger == nil {
		return nil, errors.Error("logger is nil")
	}
	if c.HTTPReg == nil {
		return nil, errors.Error("http registrar is nil")
	}

	maxReqs := c.MaxRequests
	if maxReqs <= 0 {
		maxReqs = maxBufferedRequests
	}

	retention := c.Retention
	if retention <= 0 {
		retention = defaultRetention
	}

	a = &Analysis{
		logger:      c.Logger,
		httpReg:     c.HTTPReg,
		enabled:     c.Enabled,
		retention:   retention,
		maxRequests: maxReqs,
		requests:    make([]*RequestAnalysis, 0, maxReqs),
		statsSince:  time.Now(),
	}

	a.initStats()

	// Open the persistent database, if a data directory is provided.
	if c.DataDir != "" {
		a.dbPath = filepath.Join(c.DataDir, dbFileName)

		err = os.MkdirAll(c.DataDir, 0o755)
		if err != nil {
			return nil, fmt.Errorf("creating data directory: %w", err)
		}

		a.db, err = bolt.Open(a.dbPath, 0o644, &bolt.Options{
			Timeout: time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("opening database: %w", err)
		}

		err = a.db.Update(func(tx *bolt.Tx) (err error) {
			_, err = tx.CreateBucketIfNotExists([]byte(requestsBucket))

			return err
		})
		if err != nil {
			return nil, fmt.Errorf("creating bucket: %w", err)
		}

		err = a.loadRecent()
		if err != nil {
			return nil, fmt.Errorf("loading recent requests: %w", err)
		}

		// Clean up records beyond the retention period left over from a
		// previous run.
		err = a.cleanupLocked(time.Now())
		if err != nil {
			a.logger.Warn("cleaning up old analysis records", "error", err)
		}
	} else {
		a.logger.Info("dns analysis running in memory-only mode")
	}

	return a, nil
}

// initStats initializes the stats maps.
func (a *Analysis) initStats() {
	a.stats = StatsSummary{
		ByProtocol:     make(map[string]int64),
		ByRCode:        make(map[string]int64),
		ByFilterReason: make(map[string]int64),
		ByUpstream:     make(map[string]int64),
	}
}

// Start registers HTTP handlers.
func (a *Analysis) Start() {
	a.httpReg.Register(http.MethodGet, "/control/dns_analysis/stats", a.handleStats)
	a.httpReg.Register(http.MethodGet, "/control/dns_analysis/requests", a.handleRequests)
	a.httpReg.Register(http.MethodGet, "/control/dns_analysis/config", a.handleConfig)
	a.httpReg.Register(http.MethodPut, "/control/dns_analysis/config/update", a.handleConfigUpdate)
	a.httpReg.Register(http.MethodPost, "/control/dns_analysis/reset", a.handleReset)

	a.logger.Info("dns analysis started", "enabled", a.enabled, "max_requests", a.maxRequests)
}

// Close stops the DNS analysis module and closes the persistent database.
func (a *Analysis) Close() (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.requests = nil

	if a.db != nil {
		err = a.db.Close()
		a.db = nil
		if err != nil {
			return fmt.Errorf("closing database: %w", err)
		}
	}

	return nil
}

// SetEnabled enables or disables DNS analysis.
func (a *Analysis) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.enabled = enabled
	if enabled {
		a.statsSince = time.Now()
		a.initStats()
	}
}

// Enabled returns whether DNS analysis is enabled.
func (a *Analysis) Enabled() (enabled bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.enabled
}

// Record records a DNS request analysis.  It is called for each processed
// request.  ra must not be nil.
func (a *Analysis) Record(ra *RequestAnalysis) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return
	}

	// Persist to disk first, so that data is not lost even if the process
	// crashes right after.
	if a.db != nil {
		err := a.putLocked(ra)
		if err != nil {
			a.logger.Error("writing analysis record", "error", err)
		}
	}

	// Prune old requests beyond retention period.
	cutoff := time.Now().Add(-a.retention)
	kept := a.requests[:0]
	for _, r := range a.requests {
		if r.Timestamp.After(cutoff) {
			kept = append(kept, r)
		}
	}
	a.requests = kept

	// Add the new request.
	if len(a.requests) >= a.maxRequests {
		// Ring buffer: drop the oldest.
		copy(a.requests, a.requests[1:])
		a.requests = a.requests[:a.maxRequests-1]
	}
	a.requests = append(a.requests, ra)

	// Periodically clean up expired records from the database.
	a.writeCount++
	if a.db != nil && a.writeCount >= cleanupEvery {
		a.writeCount = 0

		err := a.cleanupLocked(time.Now())
		if err != nil {
			a.logger.Error("cleaning up analysis records", "error", err)
		}
	}

	// Update aggregated stats.
	a.updateStats(ra)
}

// putLocked writes the request to the database.  a.mu must be locked.
func (a *Analysis) putLocked(ra *RequestAnalysis) (err error) {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, uint64(ra.Timestamp.UnixNano()))

	val, err := json.Marshal(ra)
	if err != nil {
		return fmt.Errorf("marshaling record: %w", err)
	}

	return a.db.Update(func(tx *bolt.Tx) (err error) {
		b := tx.Bucket([]byte(requestsBucket))
		if b == nil {
			return errors.Error("bucket not found")
		}

		return b.Put(key, val)
	})
}

// cleanupLocked removes records older than the retention period from the
// database.  a.mu must be locked.
func (a *Analysis) cleanupLocked(now time.Time) (err error) {
	if a.db == nil {
		return nil
	}

	cutoff := now.Add(-a.retention)
	cutoffKey := make([]byte, 8)
	binary.BigEndian.PutUint64(cutoffKey, uint64(cutoff.UnixNano()))

	return a.db.Update(func(tx *bolt.Tx) (err error) {
		b := tx.Bucket([]byte(requestsBucket))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, _ := c.First(); k != nil && string(k) <= string(cutoffKey); k, _ = c.Next() {
			err = c.Delete()
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// loadRecent loads the most recent requests from the database into the memory
// buffer.  a.mu must be locked.
func (a *Analysis) loadRecent() (err error) {
	if a.db == nil {
		return nil
	}

	a.requests = a.requests[:0]

	return a.db.View(func(tx *bolt.Tx) (err error) {
		b := tx.Bucket([]byte(requestsBucket))
		if b == nil {
			return nil
		}

		// Iterate backwards from the newest record.
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			ra := &RequestAnalysis{}
			err = json.Unmarshal(v, ra)
			if err != nil {
				a.logger.Warn("decoding analysis record", "error", err)

				continue
			}

			a.requests = append(a.requests, ra)
			if len(a.requests) >= a.maxRequests {
				break
			}
		}

		// Reverse to chronological order.
		sort.SliceStable(a.requests, func(i, j int) (less bool) {
			return a.requests[i].Timestamp.Before(a.requests[j].Timestamp)
		})

		return nil
	})
}

// updateStats updates the aggregated statistics with the given request.
func (a *Analysis) updateStats(ra *RequestAnalysis) {
	s := &a.stats

	s.TotalRequests++
	s.ByProtocol[ra.Protocol]++
	s.ByRCode[ra.ResponseCodeName]++
	s.ByFilterReason[ra.Filtering.Reason]++

	if ra.Upstream.Address != "" {
		s.ByUpstream[ra.Upstream.Address]++
	}

	if ra.Cache.Hit {
		s.CacheHitRate = (s.CacheHitRate*float64(s.TotalRequests-1) + 1) / float64(s.TotalRequests)
	} else {
		s.CacheHitRate = s.CacheHitRate * float64(s.TotalRequests-1) / float64(s.TotalRequests)
	}

	s.AvgLatencyNs = (s.AvgLatencyNs*int64(s.TotalRequests-1) + ra.Timeline.TotalDuration) / int64(s.TotalRequests)
	if ra.Upstream.Duration > 0 {
		upstreamCount := s.ByUpstream[ra.Upstream.Address]
		if upstreamCount <= 1 {
			s.AvgUpstreamLatencyNs = ra.Upstream.Duration
		} else {
			s.AvgUpstreamLatencyNs = (s.AvgUpstreamLatencyNs*int64(upstreamCount-1) + ra.Upstream.Duration) / int64(upstreamCount)
		}
	}

	if ra.Filtering.Matched && (ra.Filtering.Reason == "FilteredBlockList" || ra.Filtering.Reason == "FilteredSafeBrowsing" || ra.Filtering.Reason == "FilteredParental" || ra.Filtering.Reason == "FilteredBlockedService") {
		s.BlockedCount++
	}

	if ra.Filtering.Matched && (ra.Filtering.Reason == "Rewritten" || ra.Filtering.Reason == "RewrittenRule" || ra.Filtering.Reason == "FilteredSafeSearch") {
		s.ModifiedCount++
	}

	if ra.Error != "" {
		s.ErrorCount++
	}
}

// getRequestsInRange returns requests within the given time range.
func (a *Analysis) getRequestsInRange(start, end time.Time) (reqs []*RequestAnalysis) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	reqs = make([]*RequestAnalysis, 0)
	for _, r := range a.requests {
		if r.Timestamp.After(start) && r.Timestamp.Before(end) {
			reqs = append(reqs, r)
		}
	}

	return reqs
}

// getStatsInRange returns aggregated stats for the given time range.
func (a *Analysis) getStatsInRange(start, end time.Time) (s *StatsSummary) {
	reqs := a.getRequestsInRange(start, end)
	if len(reqs) == 0 {
		return &StatsSummary{
			ByProtocol:     make(map[string]int64),
			ByRCode:        make(map[string]int64),
			ByFilterReason: make(map[string]int64),
			ByUpstream:     make(map[string]int64),
		}
	}

	s = &StatsSummary{
		ByProtocol:     make(map[string]int64),
		ByRCode:        make(map[string]int64),
		ByFilterReason: make(map[string]int64),
		ByUpstream:     make(map[string]int64),
	}

	for _, ra := range reqs {
		s.TotalRequests++
		s.ByProtocol[ra.Protocol]++
		s.ByRCode[ra.ResponseCodeName]++
		s.ByFilterReason[ra.Filtering.Reason]++

		if ra.Upstream.Address != "" {
			s.ByUpstream[ra.Upstream.Address]++
		}

		if ra.Cache.Hit {
			s.CacheHitRate++
		}

		s.AvgLatencyNs += ra.Timeline.TotalDuration
		if ra.Upstream.Duration > 0 {
			s.AvgUpstreamLatencyNs += ra.Upstream.Duration
		}

		if ra.Filtering.Matched && (ra.Filtering.Reason == "FilteredBlockList" || ra.Filtering.Reason == "FilteredSafeBrowsing" || ra.Filtering.Reason == "FilteredParental" || ra.Filtering.Reason == "FilteredBlockedService") {
			s.BlockedCount++
		}

		if ra.Filtering.Matched && (ra.Filtering.Reason == "Rewritten" || ra.Filtering.Reason == "RewrittenRule" || ra.Filtering.Reason == "FilteredSafeSearch") {
			s.ModifiedCount++
		}

		if ra.Error != "" {
			s.ErrorCount++
		}
	}

	n := int64(len(reqs))
	if n > 0 {
		s.CacheHitRate = s.CacheHitRate / float64(n)
		s.AvgLatencyNs = s.AvgLatencyNs / n
		s.AvgUpstreamLatencyNs = s.AvgUpstreamLatencyNs / n
	}

	return s
}

// parsePeriod parses the period query parameter (in milliseconds) and returns
// the start and end times.  If period is empty or invalid, the default of 1
// hour is used.
func parsePeriod(periodStr string) (start, end time.Time) {
	period := time.Hour
	if periodStr != "" {
		if ms, err := time.ParseDuration(periodStr + "ms"); err == nil && ms > 0 {
			period = ms
		}
	}

	end = time.Now()
	start = end.Add(-period)

	return start, end
}

// handleStats is the handler for GET /control/dns_analysis/stats.
func (a *Analysis) handleStats(w http.ResponseWriter, r *http.Request) {
	start, end := parsePeriod(r.URL.Query().Get("period"))

	stats := a.getStatsInRange(start, end)

	aghhttp.WriteJSONResponseOK(r.Context(), a.logger, w, r, stats)
}

// handleRequests is the handler for GET /control/dns_analysis/requests.
func (a *Analysis) handleRequests(w http.ResponseWriter, r *http.Request) {
	start, end := parsePeriod(r.URL.Query().Get("period"))

	reqs := a.getRequestsInRange(start, end)

	// Sort by timestamp descending (newest first).
	sort.SliceStable(reqs, func(i, j int) (less bool) {
		return reqs[j].Timestamp.Before(reqs[i].Timestamp)
	})

	aghhttp.WriteJSONResponseOK(r.Context(), a.logger, w, r, reqs)
}

// handleConfig is the handler for GET /control/dns_analysis/config.
func (a *Analysis) handleConfig(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	resp := struct {
		Enabled     bool          `json:"enabled"`
		Retention   time.Duration `json:"retention"`
		MaxRequests int           `json:"max_requests"`
	}{
		Enabled:     a.enabled,
		Retention:   a.retention,
		MaxRequests: a.maxRequests,
	}

	aghhttp.WriteJSONResponseOK(r.Context(), a.logger, w, r, resp)
}

// handleConfigUpdate is the handler for PUT /control/dns_analysis/config/update.
func (a *Analysis) handleConfigUpdate(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Enabled     *bool         `json:"enabled"`
		Retention   time.Duration `json:"retention"`
		MaxRequests *int          `json:"max_requests"`
	}{}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if req.Enabled != nil {
		a.enabled = *req.Enabled
		if a.enabled {
			a.statsSince = time.Now()
			a.initStats()
		}
	}

	if req.Retention > 0 {
		a.retention = req.Retention
	}

	if req.MaxRequests != nil && *req.MaxRequests > 0 {
		a.maxRequests = *req.MaxRequests
		// Trim if needed.
		if len(a.requests) > a.maxRequests {
			a.requests = a.requests[len(a.requests)-a.maxRequests:]
		}
	}

	aghhttp.WriteJSONResponseOK(r.Context(), a.logger, w, r, struct{ OK bool }{OK: true})
}

// handleReset is the handler for POST /control/dns_analysis/reset.
func (a *Analysis) handleReset(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.requests = a.requests[:0]
	a.statsSince = time.Now()
	a.initStats()

	// Clear the persistent database as well.
	if a.db != nil {
		err := a.db.Update(func(tx *bolt.Tx) (err error) {
			b := tx.Bucket([]byte(requestsBucket))
			if b == nil {
				return nil
			}

			return b.ForEach(func(k, _ []byte) (err error) {
				return b.Delete(k)
			})
		})
		if err != nil {
			a.logger.Error("clearing analysis database", "error", err)
		}
	}

	aghhttp.WriteJSONResponseOK(r.Context(), a.logger, w, r, struct{ OK bool }{OK: true})
}

// reasonToString converts a filtering reason to a human-readable string.
func reasonToString(reason filtering.Reason) (s string) {
	switch reason {
	case filtering.NotFilteredNotFound:
		return "NotFilteredNotFound"
	case filtering.NotFilteredAllowList:
		return "NotFilteredAllowList"
	case filtering.NotFilteredError:
		return "NotFilteredError"
	case filtering.FilteredBlockList:
		return "FilteredBlockList"
	case filtering.FilteredSafeBrowsing:
		return "FilteredSafeBrowsing"
	case filtering.FilteredParental:
		return "FilteredParental"
	case filtering.FilteredSafeSearch:
		return "FilteredSafeSearch"
	case filtering.FilteredBlockedService:
		return "FilteredBlockedService"
	case filtering.FilteredInvalid:
		return "FilteredInvalid"
	case filtering.Rewritten:
		return "Rewritten"
	case filtering.RewrittenRule:
		return "RewrittenRule"
	default:
		return "Unknown"
	}
}

// rcodeToString converts a DNS response code to a human-readable string.
func rcodeToString(rcode int) (s string) {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}

	return "Unknown"
}

// Context type for passing analysis data through the request pipeline.
type analysisContextKey struct{}

// WithAnalysis returns a context with the analysis module attached.
func WithAnalysis(ctx context.Context, a *Analysis) (c context.Context) {
	return context.WithValue(ctx, analysisContextKey{}, a)
}

// FromContext returns the analysis module from the context, or nil.
func FromContext(ctx context.Context) (a *Analysis) {
	a, _ = ctx.Value(analysisContextKey{}).(*Analysis)

	return a
}
