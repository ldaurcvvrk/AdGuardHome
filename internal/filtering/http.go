package filtering

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/miekg/dns"
)

// pathMatchesAny returns true if path matches at least one of the given
// patterns.
func pathMatchesAny(patterns []string, path string) (ok bool) {
	for _, p := range patterns {
		if m, err := filepath.Match(p, path); err == nil && m {
			return true
		}
	}

	return false
}

// validateFilterURL validates the filter list URL or file name.
func (d *DNSFilter) validateFilterURL(urlStr string) (err error) {
	defer func() { err = errors.Annotate(err, "checking filter: %w") }()

	if filepath.IsAbs(urlStr) {
		urlStr = filepath.Clean(urlStr)
		_, err = os.Stat(urlStr)
		if err != nil {
			// Don't wrap the error since it's informative enough as is.
			return err
		}

		if !pathMatchesAny(d.safeFSPatterns, urlStr) {
			return fmt.Errorf("path %q does not match safe patterns", urlStr)
		}

		return nil
	}

	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = urlutil.ValidateHTTPURL(u)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return nil
}

type filterAddJSON struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Whitelist bool   `json:"whitelist"`
}

func (d *DNSFilter) handleFilteringAddURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := d.logger

	fj := filterAddJSON{}
	err := json.NewDecoder(r.Body).Decode(&fj)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Failed to parse request body json: %s",
			err,
		)

		return
	}

	err = d.validateFilterURL(fj.URL)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	// Check for duplicates
	if d.filterExists(fj.URL) {
		err = errFilterExists
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Filter with URL %q: %s",
			fj.URL,
			err,
		)

		return
	}

	// Set necessary properties
	filt := FilterYAML{
		Enabled: true,
		URL:     fj.URL,
		Name:    fj.Name,
		white:   fj.Whitelist,
		Filter: Filter{
			ID: d.idGen.next(),
		},
	}

	// Download the filter contents
	ok, err := d.update(&filt)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Couldn't fetch filter from URL %q: %s",
			filt.URL,
			err,
		)

		return
	}

	if !ok {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Filter with URL %q is invalid (maybe it points to blank page?)",
			filt.URL,
		)

		return
	}

	// URL is assumed valid so append it to filters, update config, write new
	// file and reload it to engines.
	err = d.filterAdd(filt)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Filter with URL %q: %s",
			filt.URL,
			err,
		)

		return
	}

	d.conf.ConfModifier.Apply(ctx)
	d.EnableFilters(true)

	_, err = fmt.Fprintf(w, "OK %d rules\n", filt.RulesCount)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusInternalServerError,
			"Couldn't write body: %s",
			err,
		)
	}
}

func (d *DNSFilter) handleFilteringRemoveURL(w http.ResponseWriter, r *http.Request) {
	type request struct {
		URL       string `json:"url"`
		Whitelist bool   `json:"whitelist"`
	}

	ctx := r.Context()

	req := request{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			d.logger,
			r,
			w,
			http.StatusBadRequest,
			"failed to parse request body json: %s",
			err,
		)

		return
	}

	var deleted FilterYAML
	func() {
		d.conf.filtersMu.Lock()
		defer d.conf.filtersMu.Unlock()

		filters := &d.conf.Filters
		if req.Whitelist {
			filters = &d.conf.WhitelistFilters
		}

		delIdx := slices.IndexFunc(*filters, func(flt FilterYAML) bool {
			return flt.URL == req.URL
		})
		if delIdx == -1 {
			d.logger.ErrorContext(
				ctx,
				"deleting filter",
				"url", req.URL,
				slogutil.KeyError, errFilterNotExist,
			)

			return
		}

		deleted = (*filters)[delIdx]
		p := deleted.Path(d.conf.DataDir)
		err = os.Rename(p, p+".old")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			d.logger.ErrorContext(
				ctx,
				"renaming filter file",
				"id", deleted.ID,
				"path", p,
				slogutil.KeyError, err,
			)

			return
		}

		*filters = slices.Delete(*filters, delIdx, delIdx+1)

		d.logger.InfoContext(ctx, "deleted filter", "id", deleted.ID)
	}()

	d.conf.ConfModifier.Apply(ctx)
	d.EnableFilters(true)

	// NOTE: The old files "filter.txt.old" aren't deleted.  It's not really
	// necessary, but will require the additional complicated code to run
	// after enableFilters is done.
	//
	// TODO(a.garipov): Make sure the above comment is true.

	_, err = fmt.Fprintf(w, "OK %d rules\n", deleted.RulesCount)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			d.logger,
			r,
			w,
			http.StatusInternalServerError,
			"couldn't write body: %s",
			err,
		)
	}
}

type filterURLReqData struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type filterURLReq struct {
	Data      *filterURLReqData `json:"data"`
	URL       string            `json:"url"`
	Whitelist bool              `json:"whitelist"`
}

func (d *DNSFilter) handleFilteringSetURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := d.logger

	fj := filterURLReq{}
	err := json.NewDecoder(r.Body).Decode(&fj)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "decoding request: %s", err)

		return
	}

	if fj.Data == nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"%s",
			errors.Error("data is absent"),
		)

		return
	}

	err = d.validateFilterURL(fj.Data.URL)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "invalid url: %s", err)

		return
	}

	filt := FilterYAML{
		Enabled: fj.Data.Enabled,
		Name:    fj.Data.Name,
		URL:     fj.Data.URL,
	}

	restart, err := d.filterSetProperties(fj.URL, filt, fj.Whitelist)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	d.conf.ConfModifier.Apply(ctx)
	if restart {
		d.EnableFilters(true)
	}
}

// filteringRulesReq is the JSON structure for settings custom filtering rules.
type filteringRulesReq struct {
	Rules []string `json:"rules"`
}

func (d *DNSFilter) handleFilteringSetRules(w http.ResponseWriter, r *http.Request) {
	if aghhttp.WriteTextPlainDeprecated(w, r) {
		return
	}

	ctx := r.Context()

	req := &filteringRulesReq{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, d.logger, r, w, http.StatusBadRequest, "reading req: %s", err)

		return
	}

	d.conf.UserRules = req.Rules
	d.conf.ConfModifier.Apply(ctx)
	d.EnableFilters(true)
}

func (d *DNSFilter) handleFilteringRefresh(w http.ResponseWriter, r *http.Request) {
	type Req struct {
		White bool `json:"whitelist"`
	}
	var err error

	ctx := r.Context()
	l := d.logger

	req := Req{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	var ok bool
	resp := struct {
		Updated int `json:"updated"`
	}{}
	resp.Updated, _, ok = d.tryRefreshFilters(!req.White, req.White, true)
	if !ok {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusInternalServerError,
			"filters update procedure is already running",
		)

		return
	}

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, resp)
}

type filterJSON struct {
	URL         string `json:"url"`
	Name        string `json:"name"`
	LastUpdated string `json:"last_updated,omitempty"`

	ID rulelist.APIID `json:"id"`

	RulesCount uint64 `json:"rules_count"`
	Enabled    bool   `json:"enabled"`
}

type filteringConfig struct {
	Filters          []filterJSON `json:"filters"`
	WhitelistFilters []filterJSON `json:"whitelist_filters"`
	UserRules        []string     `json:"user_rules"`
	Interval         uint32       `json:"interval"` // in hours
	Enabled          bool         `json:"enabled"`
}

func filterToJSON(f FilterYAML) filterJSON {
	fj := filterJSON{
		// #nosec G115 -- The overflow is required for backwards compatibility.
		ID:      rulelist.APIID(f.ID),
		Enabled: f.Enabled,
		URL:     f.URL,
		Name:    f.Name,
		// #nosec G115 -- The number of rules must not be negative.
		RulesCount: uint64(f.RulesCount),
	}

	if !f.LastUpdated.IsZero() {
		fj.LastUpdated = f.LastUpdated.Format(time.RFC3339)
	}

	return fj
}

// Get filtering configuration
func (d *DNSFilter) handleFilteringStatus(w http.ResponseWriter, r *http.Request) {
	resp := filteringConfig{}
	d.conf.filtersMu.RLock()
	resp.Enabled = d.conf.FilteringEnabled
	resp.Interval = d.conf.FiltersUpdateIntervalHours
	for _, f := range d.conf.Filters {
		fj := filterToJSON(f)
		resp.Filters = append(resp.Filters, fj)
	}
	for _, f := range d.conf.WhitelistFilters {
		fj := filterToJSON(f)
		resp.WhitelistFilters = append(resp.WhitelistFilters, fj)
	}
	resp.UserRules = d.conf.UserRules
	d.conf.filtersMu.RUnlock()

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, resp)
}

// Set filtering configuration
func (d *DNSFilter) handleFilteringConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := d.logger

	req := filteringConfig{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	if !ValidateUpdateIvl(req.Interval) {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "Unsupported interval")

		return
	}

	func() {
		d.conf.filtersMu.Lock()
		defer d.conf.filtersMu.Unlock()

		d.conf.FilteringEnabled = req.Enabled
		d.conf.FiltersUpdateIntervalHours = req.Interval
	}()

	d.conf.ConfModifier.Apply(ctx)
	d.EnableFilters(true)
}

type checkHostRespRule struct {
	Text string `json:"text"`

	FilterListID rulelist.APIID `json:"filter_list_id"`
}

type checkHostResp struct {
	Reason string `json:"reason"`

	// Rule is the text of the matched rule.
	//
	// Deprecated: Use Rules[*].Text.
	Rule string `json:"rule"`

	Rules []*checkHostRespRule `json:"rules"`

	// for FilteredBlockedService:
	SvcName string `json:"service_name"`

	// for Rewrite:
	CanonName string       `json:"cname"`    // CNAME value
	IPList    []netip.Addr `json:"ip_addrs"` // list of IP addresses

	// FilterID is the ID of the rule's filter list.
	//
	// Deprecated: Use Rules[*].FilterListID.
	FilterID rulelist.APIID `json:"filter_id"`
}

// handleCheckHost is the handler for the GET /control/filtering/check_host HTTP
// API.
func (d *DNSFilter) handleCheckHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := d.logger

	query := r.URL.Query()
	host := query.Get("name")
	if host == "" {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			`query parameter "name" is required`,
		)

		return
	}

	qTypeStr := query.Get("qtype")
	qType, err := stringToDNSType(qTypeStr)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusUnprocessableEntity,
			"bad qtype query parameter: %q",
			qTypeStr,
		)

		return
	}

	setts := d.Settings()
	setts.FilteringEnabled = true
	setts.ProtectionEnabled = true

	cli := query.Get("client")
	addr, err := netip.ParseAddr(cli)
	if err == nil {
		d.ApplyAdditionalFiltering(addr, "", setts)
	} else if cli != "" {
		// TODO(s.chzhen):  Set [Settings.ClientName] once urlfilter supports
		// multiple client names.  This will handle the case when a rule exists
		// but the persistent client does not.
		d.ApplyAdditionalFiltering(netip.Addr{}, cli, setts)
	} else {
		// Apply blocked services filtering even if the client is not known,
		// because blocked services rules don't depend on the client and should
		// be applied regardless of whether the client is known or not.
		d.ApplyBlockedServices(setts)
	}

	result, err := d.CheckHost(host, qType, setts)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusInternalServerError,
			"couldn't apply filtering: %s: %s",
			host,
			err,
		)

		return
	}

	rulesLen := len(result.Rules)
	resp := checkHostResp{
		Reason:    result.Reason.String(),
		SvcName:   result.ServiceName,
		CanonName: result.CanonName,
		IPList:    result.IPList,
		Rules:     make([]*checkHostRespRule, len(result.Rules)),
	}

	if rulesLen > 0 {
		resp.FilterID = result.Rules[0].FilterListID
		resp.Rule = result.Rules[0].Text
	}

	for i, r := range result.Rules {
		resp.Rules[i] = &checkHostRespRule{
			FilterListID: r.FilterListID,
			Text:         r.Text,
		}
	}

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, resp)
}

// stringToDNSType is a helper function that converts a string to DNS type.  If
// the string is empty, it returns the default value [dns.TypeA].
func stringToDNSType(str string) (qtype uint16, err error) {
	if str == "" {
		return dns.TypeA, nil
	}

	qtype, ok := dns.StringToType[str]
	if ok {
		return qtype, nil
	}

	// typePref is a prefix for DNS types from experimental RFCs.
	const typePref = "TYPE"

	if !strings.HasPrefix(str, typePref) {
		return 0, errors.ErrBadEnumValue
	}

	val, err := strconv.ParseUint(str[len(typePref):], 10, 16)
	if err != nil {
		return 0, errors.ErrBadEnumValue
	}

	return uint16(val), nil
}

// setProtectedBool sets the value of a boolean pointer under a lock.  l must
// protect the value under ptr.
//
// TODO(e.burkov):  Make it generic?
func setProtectedBool(mu *sync.RWMutex, ptr *bool, val bool) {
	mu.Lock()
	defer mu.Unlock()

	*ptr = val
}

// protectedBool gets the value of a boolean pointer under a read lock.  l must
// protect the value under ptr.
//
// TODO(e.burkov):  Make it generic?
func protectedBool(mu *sync.RWMutex, ptr *bool) (val bool) {
	mu.RLock()
	defer mu.RUnlock()

	return *ptr
}

// handleSafeBrowsingEnable is the handler for the POST
// /control/safebrowsing/enable HTTP API.
func (d *DNSFilter) handleSafeBrowsingEnable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.SafeBrowsingEnabled, true)
	d.conf.ConfModifier.Apply(r.Context())
}

// handleSafeBrowsingDisable is the handler for the POST
// /control/safebrowsing/disable HTTP API.
func (d *DNSFilter) handleSafeBrowsingDisable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.SafeBrowsingEnabled, false)
	d.conf.ConfModifier.Apply(r.Context())
}

// handleSafeBrowsingStatus is the handler for the GET
// /control/safebrowsing/status HTTP API.
func (d *DNSFilter) handleSafeBrowsingStatus(w http.ResponseWriter, r *http.Request) {
	resp := &struct {
		Enabled bool `json:"enabled"`
	}{
		Enabled: protectedBool(d.confMu, &d.conf.SafeBrowsingEnabled),
	}

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, resp)
}

// handleParentalEnable is the handler for the POST /control/parental/enable
// HTTP API.
func (d *DNSFilter) handleParentalEnable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.ParentalEnabled, true)
	d.conf.ConfModifier.Apply(r.Context())
}

// handleParentalDisable is the handler for the POST /control/parental/disable
// HTTP API.
func (d *DNSFilter) handleParentalDisable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.ParentalEnabled, false)
	d.conf.ConfModifier.Apply(r.Context())
}

// handleParentalStatus is the handler for the GET /control/parental/status
// HTTP API.
func (d *DNSFilter) handleParentalStatus(w http.ResponseWriter, r *http.Request) {
	resp := &struct {
		Enabled bool `json:"enabled"`
	}{
		Enabled: protectedBool(d.confMu, &d.conf.ParentalEnabled),
	}

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, resp)
}

// RegisterFilteringHandlers - register handlers
func (d *DNSFilter) RegisterFilteringHandlers() {
	registerHTTP := d.conf.HTTPReg.Register

	registerHTTP(http.MethodPost, "/control/safebrowsing/enable", d.handleSafeBrowsingEnable)
	registerHTTP(http.MethodPost, "/control/safebrowsing/disable", d.handleSafeBrowsingDisable)
	registerHTTP(http.MethodGet, "/control/safebrowsing/status", d.handleSafeBrowsingStatus)

	registerHTTP(http.MethodPost, "/control/parental/enable", d.handleParentalEnable)
	registerHTTP(http.MethodPost, "/control/parental/disable", d.handleParentalDisable)
	registerHTTP(http.MethodGet, "/control/parental/status", d.handleParentalStatus)

	registerHTTP(http.MethodPost, "/control/safesearch/enable", d.handleSafeSearchEnable)
	registerHTTP(http.MethodPost, "/control/safesearch/disable", d.handleSafeSearchDisable)
	registerHTTP(http.MethodGet, "/control/safesearch/status", d.handleSafeSearchStatus)
	registerHTTP(http.MethodPut, "/control/safesearch/settings", d.handleSafeSearchSettings)

	registerHTTP(http.MethodGet, "/control/rewrite/list", d.handleRewriteList)
	registerHTTP(http.MethodGet, "/control/rewrite/settings", d.handleRewriteSettings)
	registerHTTP(http.MethodPost, "/control/rewrite/add", d.handleRewriteAdd)
	registerHTTP(http.MethodPost, "/control/rewrite/delete", d.handleRewriteDelete)
	registerHTTP(http.MethodPut, "/control/rewrite/settings/update", d.handleRewriteSettingsUpdate)
	registerHTTP(http.MethodPut, "/control/rewrite/update", d.handleRewriteUpdate)

	registerHTTP(http.MethodGet, "/control/blocked_services/services", d.handleBlockedServicesIDs)
	registerHTTP(http.MethodGet, "/control/blocked_services/all", d.handleBlockedServicesAll)

	// Deprecated handlers.
	registerHTTP(http.MethodGet, "/control/blocked_services/list", d.handleBlockedServicesList)
	registerHTTP(http.MethodPost, "/control/blocked_services/set", d.handleBlockedServicesSet)

	registerHTTP(http.MethodGet, "/control/blocked_services/get", d.handleBlockedServicesGet)
	registerHTTP(http.MethodPut, "/control/blocked_services/update", d.handleBlockedServicesUpdate)

	registerHTTP(http.MethodGet, "/control/filtering/status", d.handleFilteringStatus)
	registerHTTP(http.MethodPost, "/control/filtering/config", d.handleFilteringConfig)
	registerHTTP(http.MethodPost, "/control/filtering/add_url", d.handleFilteringAddURL)
	registerHTTP(http.MethodPost, "/control/filtering/remove_url", d.handleFilteringRemoveURL)
	registerHTTP(http.MethodPost, "/control/filtering/set_url", d.handleFilteringSetURL)
	registerHTTP(http.MethodPost, "/control/filtering/refresh", d.handleFilteringRefresh)
	registerHTTP(http.MethodPost, "/control/filtering/set_rules", d.handleFilteringSetRules)
	registerHTTP(http.MethodGet, "/control/filtering/check_host", d.handleCheckHost)
}

// maxUpdateIvlHours is the maximum allowed filter update interval in hours.
const maxUpdateIvlHours = 365 * 24

// ValidateUpdateIvl returns false if i is not a valid filters update interval.
func ValidateUpdateIvl(i uint32) (ok bool) {
	return i <= maxUpdateIvlHours
}

// ApplyAdditionalFiltering applies additional filtering settings based on the
// client's IP address and name.  It applies the blocked services configuration
// to the settings.  setts must not be nil.
func (d *DNSFilter) ApplyAdditionalFiltering(clientIP netip.Addr, clientName string, setts *Settings) {
	d.ApplyBlockedServices(setts)
}

// handleSafeSearchEnable is the handler for the POST
// /control/safesearch/enable HTTP API.
func (d *DNSFilter) handleSafeSearchEnable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.SafeSearchConf.Enabled, true)
	d.conf.ConfModifier.Apply(r.Context())
}

// handleSafeSearchDisable is the handler for the POST
// /control/safesearch/disable HTTP API.
func (d *DNSFilter) handleSafeSearchDisable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.SafeSearchConf.Enabled, false)
	d.conf.ConfModifier.Apply(r.Context())
}

// handleSafeSearchStatus is the handler for the GET
// /control/safesearch/status HTTP API.
func (d *DNSFilter) handleSafeSearchStatus(w http.ResponseWriter, r *http.Request) {
	resp := &struct {
		Enabled bool `json:"enabled"`
	}{
		Enabled: protectedBool(d.confMu, &d.conf.SafeSearchConf.Enabled),
	}

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, resp)
}

// handleSafeSearchSettings is the handler for the PUT
// /control/safesearch/settings HTTP API.
func (d *DNSFilter) handleSafeSearchSettings(w http.ResponseWriter, r *http.Request) {
	conf := SafeSearchConfig{}
	err := json.NewDecoder(r.Body).Decode(&conf)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "decoding settings: %s", err)

		return
	}

	d.confMu.Lock()
	d.conf.SafeSearchConf = conf
	d.confMu.Unlock()

	if d.safeSearch != nil {
		err = d.safeSearch.Update(context.TODO(), conf)
		if err != nil {
			aghhttp.Error(r, w, http.StatusInternalServerError, "updating safe search: %s", err)

			return
		}
	}

	d.conf.ConfModifier.Apply(r.Context())

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, conf)
}

// handleRewriteList is the handler for the GET /control/rewrite/list HTTP API.
func (d *DNSFilter) handleRewriteList(w http.ResponseWriter, r *http.Request) {
	d.confMu.RLock()
	rewrites := cloneRewrites(d.conf.Rewrites)
	d.confMu.RUnlock()

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, rewrites)
}

// handleRewriteSettings is the handler for the GET /control/rewrite/settings
// HTTP API.
func (d *DNSFilter) handleRewriteSettings(w http.ResponseWriter, r *http.Request) {
	d.confMu.RLock()
	defer d.confMu.RUnlock()

	resp := struct {
		Enabled  bool             `json:"enabled"`
		Rewrites []*LegacyRewrite `json:"rewrites"`
	}{
		Enabled:  d.conf.RewritesEnabled,
		Rewrites: cloneRewrites(d.conf.Rewrites),
	}

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, resp)
}

// handleRewriteAdd is the handler for the POST /control/rewrite/add HTTP API.
func (d *DNSFilter) handleRewriteAdd(w http.ResponseWriter, r *http.Request) {
	rw := &LegacyRewrite{}
	err := json.NewDecoder(r.Body).Decode(rw)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	err = rw.normalize()
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "normalizing: %s", err)

		return
	}

	d.confMu.Lock()
	defer d.confMu.Unlock()

	d.conf.Rewrites = append(d.conf.Rewrites, rw)
	d.conf.RewritesEnabled = true

	d.conf.ConfModifier.Apply(r.Context())

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, struct{ OK bool }{OK: true})
}

// handleRewriteDelete is the handler for the POST /control/rewrite/delete HTTP
// API.
func (d *DNSFilter) handleRewriteDelete(w http.ResponseWriter, r *http.Request) {
	rw := &LegacyRewrite{}
	err := json.NewDecoder(r.Body).Decode(rw)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	err = rw.normalize()
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "normalizing: %s", err)

		return
	}

	d.confMu.Lock()
	defer d.confMu.Unlock()

	rewrites := d.conf.Rewrites[:0]
	found := false
	for _, e := range d.conf.Rewrites {
		if e.equal(rw) {
			found = true

			continue
		}

		rewrites = append(rewrites, e)
	}

	if !found {
		aghhttp.Error(r, w, http.StatusNotFound, "rewrite not found")

		return
	}

	d.conf.Rewrites = rewrites

	d.conf.ConfModifier.Apply(r.Context())

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, struct{ OK bool }{OK: true})
}

// rewriteUpdateReq is the JSON request body for updating a legacy rewrite.
type rewriteUpdateReq struct {
	Target *LegacyRewrite `json:"target"`
	Update *LegacyRewrite `json:"update"`
}

// handleRewriteUpdate is the handler for the PUT /control/rewrite/update HTTP
// API.
func (d *DNSFilter) handleRewriteUpdate(w http.ResponseWriter, r *http.Request) {
	req := rewriteUpdateReq{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	if req.Target == nil || req.Update == nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "target and update must not be nil")

		return
	}

	err = req.Target.normalize()
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "normalizing target: %s", err)

		return
	}

	err = req.Update.normalize()
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "normalizing update: %s", err)

		return
	}

	d.confMu.Lock()
	defer d.confMu.Unlock()

	for i, e := range d.conf.Rewrites {
		if e.equal(req.Target) {
			d.conf.Rewrites[i] = req.Update

			d.conf.ConfModifier.Apply(r.Context())

			aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, struct{ OK bool }{OK: true})

			return
		}
	}

	aghhttp.Error(r, w, http.StatusNotFound, "rewrite not found")
}

// handleRewriteSettingsUpdate is the handler for the PUT
// /control/rewrite/settings/update HTTP API.
func (d *DNSFilter) handleRewriteSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Enabled  *bool            `json:"enabled"`
		Rewrites []*LegacyRewrite `json:"rewrites"`
	}{}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	for _, rw := range req.Rewrites {
		err = rw.normalize()
		if err != nil {
			aghhttp.Error(r, w, http.StatusBadRequest, "normalizing: %s", err)

			return
		}
	}

	d.confMu.Lock()
	defer d.confMu.Unlock()

	if req.Enabled != nil {
		d.conf.RewritesEnabled = *req.Enabled
	}

	if req.Rewrites != nil {
		d.conf.Rewrites = req.Rewrites
	}

	d.conf.ConfModifier.Apply(r.Context())

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, struct{ OK bool }{OK: true})
}
