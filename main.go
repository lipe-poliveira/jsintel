package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type InputType string

const (
	InputAuto   InputType = "auto"
	InputTarget InputType = "target"
	InputJS     InputType = "js"
)

type InputItem struct {
	Raw  string
	Type InputType
}

type Finding struct {
	Target         string   `json:"target"`
	Asset          string   `json:"asset,omitempty"`
	DiscoveredFrom string   `json:"discovered_from,omitempty"`
	Finding        string   `json:"finding"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	Framework      string   `json:"framework,omitempty"`
	SourceMap      string   `json:"sourcemap,omitempty"`
	SourcePaths    []string `json:"source_paths,omitempty"`
	Endpoint       string   `json:"endpoint,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	SecretType     string   `json:"secret_type,omitempty"`
	ValueRedacted  string   `json:"value_redacted,omitempty"`
	AuthHints      []string `json:"auth_hints,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	ContentType    string   `json:"content_type,omitempty"`
	StatusCode     int      `json:"status_code,omitempty"`
}

type jsAsset struct {
	URL            string
	DiscoveredFrom string
}

type secretCandidate struct {
	Kind       string
	Redacted   string
	Severity   string
	Confidence string
	Evidence   []string
}

type methodPath struct {
	Method string
	Path   string
}

type sourceMapDoc struct {
	Version        int      `json:"version"`
	File           string   `json:"file"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

var (
	reScriptSrc      = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.m?js(?:\?[^"']*)?)["']`)
	reModulePreload  = regexp.MustCompile(`(?i)<link[^>]+(?:href|src)=["']([^"']+\.m?js(?:\?[^"']*)?)["']`)
	reSourceMap      = regexp.MustCompile(`(?m)(?:\/\/|\/\*)#?\s*sourceMappingURL=([^\s*]+)`)
	reQuotedPath     = regexp.MustCompile(`["']((?:\/|\.\/|\.\.\/)[a-zA-Z0-9_\-./?=&%{}:]+)["']`)
	reQuotedURL      = regexp.MustCompile(`["'](https?:\/\/[a-zA-Z0-9._:/?&=%#\-\+]+)["']`)
	reMethodPath     = regexp.MustCompile(`(?i)\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b["'\s,:]+(\/[a-zA-Z0-9_\-./?=&%{}:]+)`)
	reFetchCall      = regexp.MustCompile(`(?i)fetch\(\s*["']([^"']+)["']`)
	reAxiosCall      = regexp.MustCompile(`(?i)axios\.(get|post|put|delete|patch|head|options)\(\s*["']([^"']+)["']`)
	reAuthHeader     = regexp.MustCompile(`(?i)(authorization|bearer|basic|x-api-key|api-key|client-secret|token)`)
	reAWSAccessKey   = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reGoogleAPIKey   = regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)
	reJWTLike        = regexp.MustCompile(`\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b`)
	reBearer         = regexp.MustCompile(`(?i)\bbearer\s+[a-zA-Z0-9_\-\.=]{16,}\b`)
	rePrivateKey     = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	reGenericSecret  = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|client[_-]?secret)\s*[:=]\s*["'][^"']{8,}["']`)
	reFirebaseConfig = regexp.MustCompile(`(?i)(firebase|authDomain|projectId|storageBucket|messagingSenderId|appId|measurementId)`)

	reNext    = regexp.MustCompile(`__NEXT_DATA__|/_next/static/|webpack://_N_E/`)
	reNuxt    = regexp.MustCompile(`window\.__NUXT__|/_nuxt/`)
	reAngular = regexp.MustCompile(`ng-version|zone\.js|angular`)
	reVite    = regexp.MustCompile(`/@vite/client|vite/client`)
	reVue     = regexp.MustCompile(`__VUE__|vuex|createApp\(`)
	reReact   = regexp.MustCompile(`react|jsx|__REACT_DEVTOOLS_GLOBAL_HOOK__`)
	reWebpack = regexp.MustCompile(`webpack://|webpackChunk`)
)

func main() {
	var (
		singleURL    = flag.String("u", "", "single target")
		listFile     = flag.String("l", "", "input file")
		inputTypeRaw = flag.String("type", "auto", "input type: auto|target|js")
		concurrency  = flag.Int("c", 20, "worker concurrency")
		timeout      = flag.Duration("timeout", 8*time.Second, "HTTP timeout")
		maxBody      = flag.Int64("max-body", 2*1024*1024, "maximum response body size")
		insecure     = flag.Bool("k", true, "disable strict TLS verification")
		noInfo       = flag.Bool("no-info", false, "omit info-level findings")
	)
	flag.Parse()

	inputType := parseInputType(*inputTypeRaw)
	if inputType == "" {
		fmt.Fprintln(os.Stderr, "invalid -type value; use auto|target|js")
		os.Exit(1)
	}

	items, err := collectInputs(*singleURL, *listFile, inputType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "input collection error: %v\n", err)
		os.Exit(1)
	}
	if len(items) == 0 {
		fmt.Fprintln(os.Stderr, "no input received")
		os.Exit(1)
	}

	if *concurrency <= 0 {
		*concurrency = 20
	}

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecure},
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	jobs := make(chan InputItem, len(items))
	out := make(chan Finding, 1024)

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				var findings []Finding
				switch item.Type {
				case InputJS:
					findings = analyzeJSURL(client, item.Raw, *maxBody)
				case InputTarget:
					findings = analyzeTarget(client, item.Raw, *maxBody)
				default:
					findings = analyzeAuto(client, item.Raw, *maxBody)
				}
				for _, f := range findings {
					if *noInfo && strings.EqualFold(f.Severity, "info") {
						continue
					}
					out <- f
				}
			}
		}()
	}

	go func() {
		for _, item := range items {
			jobs <- item
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()

	enc := json.NewEncoder(os.Stdout)
	for f := range out {
		if err := enc.Encode(f); err != nil {
			fmt.Fprintf(os.Stderr, "JSONL encode error: %v\n", err)
		}
	}
}

func parseInputType(s string) InputType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto":
		return InputAuto
	case "target":
		return InputTarget
	case "js":
		return InputJS
	default:
		return ""
	}
}

func collectInputs(singleURL, listFile string, forcedType InputType) ([]InputItem, error) {
	seen := map[string]struct{}{}
	var out []InputItem

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		t := forcedType
		if forcedType == InputAuto {
			t = guessType(v)
		}
		norm := normalizeInput(v, t)
		if norm == "" {
			return
		}
		key := string(t) + "|" + norm
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, InputItem{Raw: norm, Type: t})
	}

	if strings.TrimSpace(singleURL) != "" {
		add(singleURL)
	}

	if strings.TrimSpace(listFile) != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	stdinInfo, err := os.Stdin.Stat()
	if err == nil && (stdinInfo.Mode()&os.ModeCharDevice) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].Raw < out[j].Raw
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

func guessType(v string) InputType {
	lv := strings.ToLower(strings.TrimSpace(v))
	if strings.Contains(lv, ".js") || strings.Contains(lv, ".mjs") {
		return InputJS
	}
	return InputTarget
}

func normalizeInput(v string, t InputType) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "//") {
		v = "https:" + v
	}
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		v = "https://" + v
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return ""
	}
	if t == InputJS || t == InputTarget {
		return u.String()
	}
	return ""
}

func analyzeAuto(client *http.Client, raw string, maxBody int64) []Finding {
	if guessType(raw) == InputJS {
		return analyzeJSURL(client, raw, maxBody)
	}
	return analyzeTarget(client, raw, maxBody)
}

func analyzeTarget(client *http.Client, target string, maxBody int64) []Finding {
	resp, body, err := fetch(client, target, maxBody)
	if err != nil {
		return []Finding{{
			Target:     target,
			Finding:    "fetch_error",
			Severity:   "info",
			Confidence: "low",
			Evidence:   []string{err.Error()},
		}}
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "javascript") || looksLikeJSURL(target) || isLikelyJS(body) {
		return analyzeJSBody(client, target, target, "", resp.StatusCode, contentType, body, maxBody)
	}

	assets := discoverJSAssets(target, body)
	if len(assets) == 0 {
		return []Finding{{
			Target:      target,
			Finding:     "no_js_assets_found",
			Severity:    "info",
			Confidence:  "low",
			ContentType: contentType,
			StatusCode:  resp.StatusCode,
		}}
	}

	var all []Finding
	for _, asset := range assets {
		r2, b2, err := fetch(client, asset.URL, maxBody)
		if err != nil {
			all = append(all, Finding{
				Target:         target,
				Asset:          asset.URL,
				DiscoveredFrom: asset.DiscoveredFrom,
				Finding:        "asset_fetch_error",
				Severity:       "info",
				Confidence:     "low",
				Evidence:       []string{err.Error()},
			})
			continue
		}
		all = append(all, analyzeJSBody(
			client,
			target,
			asset.URL,
			asset.DiscoveredFrom,
			r2.StatusCode,
			strings.ToLower(r2.Header.Get("Content-Type")),
			b2,
			maxBody,
		)...)
	}
	return dedupeFindings(all)
}

func analyzeJSURL(client *http.Client, jsURL string, maxBody int64) []Finding {
	resp, body, err := fetch(client, jsURL, maxBody)
	if err != nil {
		return []Finding{{
			Target:     jsURL,
			Asset:      jsURL,
			Finding:    "asset_fetch_error",
			Severity:   "info",
			Confidence: "low",
			Evidence:   []string{err.Error()},
		}}
	}
	return dedupeFindings(analyzeJSBody(
		client,
		jsURL,
		jsURL,
		jsURL,
		resp.StatusCode,
		strings.ToLower(resp.Header.Get("Content-Type")),
		body,
		maxBody,
	))
}

func analyzeJSBody(client *http.Client, target, asset, discoveredFrom string, status int, contentType string, body []byte, maxBody int64) []Finding {
	text := string(body)
	var findings []Finding

	framework := detectFramework(text)
	authHints := detectAuthHints(text)

	if framework != "" {
		findings = append(findings, Finding{
			Target:         target,
			Asset:          asset,
			DiscoveredFrom: discoveredFrom,
			Finding:        "framework_detected",
			Severity:       "info",
			Confidence:     "high",
			Framework:      framework,
			ContentType:    contentType,
			StatusCode:     status,
			Evidence:       []string{"framework_fingerprint"},
		})
	}

	if len(authHints) > 0 {
		findings = append(findings, Finding{
			Target:         target,
			Asset:          asset,
			DiscoveredFrom: discoveredFrom,
			Finding:        "auth_hint",
			Severity:       "info",
			Confidence:     "medium",
			Framework:      framework,
			AuthHints:      authHints,
			Evidence:       []string{"auth_keywords_in_js"},
		})
	}

	sm := detectSourceMapURL(asset, text)
	if sm != "" {
		findings = append(findings, Finding{
			Target:         target,
			Asset:          asset,
			DiscoveredFrom: discoveredFrom,
			Finding:        "sourcemap_reference",
			Severity:       "medium",
			Confidence:     "high",
			Framework:      framework,
			SourceMap:      sm,
			ContentType:    contentType,
			StatusCode:     status,
			Evidence:       []string{"sourceMappingURL"},
		})

		r3, b3, err := fetch(client, sm, maxBody)
		if err == nil && r3.StatusCode >= 200 && r3.StatusCode < 300 {
			srcPaths, ev := parseSourceMapEvidence(b3)
			findings = append(findings, Finding{
				Target:         target,
				Asset:          asset,
				DiscoveredFrom: discoveredFrom,
				Finding:        "exposed_sourcemap",
				Severity:       "medium",
				Confidence:     "high",
				Framework:      framework,
				SourceMap:      sm,
				SourcePaths:    srcPaths,
				StatusCode:     r3.StatusCode,
				ContentType:    strings.ToLower(r3.Header.Get("Content-Type")),
				Evidence:       ev,
			})
		}
	}

	for _, ep := range extractEndpoints(text) {
		findings = append(findings, Finding{
			Target:         target,
			Asset:          asset,
			DiscoveredFrom: discoveredFrom,
			Finding:        "hidden_endpoint",
			Severity:       scoreEndpointSeverity(ep),
			Confidence:     "medium",
			Framework:      framework,
			Endpoint:       ep,
			AuthHints:      authHints,
			Evidence:       endpointEvidence(ep),
		})
	}

	for _, mp := range extractMethodPaths(text) {
		findings = append(findings, Finding{
			Target:         target,
			Asset:          asset,
			DiscoveredFrom: discoveredFrom,
			Finding:        "api_route_hint",
			Severity:       scoreEndpointSeverity(mp.Path),
			Confidence:     "high",
			Framework:      framework,
			Endpoint:       mp.Path,
			Methods:        []string{mp.Method},
			AuthHints:      authHints,
			Evidence:       endpointEvidence(mp.Path),
		})
	}

	for _, s := range extractSecrets(text) {
		findings = append(findings, Finding{
			Target:         target,
			Asset:          asset,
			DiscoveredFrom: discoveredFrom,
			Finding:        "secret_candidate",
			Severity:       s.Severity,
			Confidence:     s.Confidence,
			Framework:      framework,
			SecretType:     s.Kind,
			ValueRedacted:  s.Redacted,
			Evidence:       s.Evidence,
		})
	}

	return findings
}

func fetch(client *http.Client, rawURL string, maxBody int64) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "jsinte/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

func discoverJSAssets(baseURL string, html []byte) []jsAsset {
	text := string(html)
	seen := map[string]struct{}{}
	var assets []jsAsset

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		u := resolveURL(baseURL, raw)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		assets = append(assets, jsAsset{
			URL:            u,
			DiscoveredFrom: baseURL,
		})
	}

	for _, m := range reScriptSrc.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range reModulePreload.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}

	sort.Slice(assets, func(i, j int) bool { return assets[i].URL < assets[j].URL })
	return assets
}

func resolveURL(baseURL, ref string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	return base.ResolveReference(r).String()
}

func detectSourceMapURL(assetURL, js string) string {
	if m := reSourceMap.FindStringSubmatch(js); len(m) == 2 {
		return resolveURL(assetURL, m[1])
	}

	if assetURL == "" {
		return ""
	}
	u, err := url.Parse(assetURL)
	if err != nil {
		return ""
	}
	if strings.Contains(strings.ToLower(u.Path), ".js") || strings.Contains(strings.ToLower(u.Path), ".mjs") {
		u.Path = u.Path + ".map"
		return u.String()
	}
	return ""
}

func parseSourceMapEvidence(body []byte) ([]string, []string) {
	var doc sourceMapDoc
	var ev []string
	var out []string

	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, []string{"sourcemap_fetch_ok", "sourcemap_parse_failed"}
	}

	ev = append(ev, "sourcemap_fetch_ok")
	if len(doc.SourcesContent) > 0 {
		ev = append(ev, "sourcesContent_present")
	}
	if len(doc.Sources) > 0 {
		ev = append(ev, "sources_present")
	}

	seen := map[string]struct{}{}
	for _, s := range doc.Sources {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = out[:20]
	}
	return out, ev
}

func detectFramework(js string) string {
	switch {
	case reNext.MatchString(js):
		return "nextjs"
	case reNuxt.MatchString(js):
		return "nuxt"
	case reAngular.MatchString(js):
		return "angular"
	case reVite.MatchString(js):
		return "vite"
	case reVue.MatchString(js):
		return "vue"
	case reReact.MatchString(js):
		return "react"
	case reWebpack.MatchString(js):
		return "webpack"
	default:
		return ""
	}
}

func detectAuthHints(js string) []string {
	seen := map[string]struct{}{}
	var hints []string

	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		hints = append(hints, v)
	}

	if reAuthHeader.MatchString(js) {
		for _, kw := range []string{
			"authorization", "bearer", "basic", "x-api-key", "api-key", "client-secret", "token",
		} {
			if strings.Contains(strings.ToLower(js), kw) {
				add(kw)
			}
		}
	}

	sort.Strings(hints)
	return hints
}

func extractEndpoints(js string) []string {
	seen := map[string]struct{}{}
	var out []string

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || !looksInterestingPath(v) {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	for _, m := range reQuotedPath.FindAllStringSubmatch(js, -1) {
		add(m[1])
	}
	for _, m := range reQuotedURL.FindAllStringSubmatch(js, -1) {
		add(m[1])
	}
	for _, m := range reFetchCall.FindAllStringSubmatch(js, -1) {
		add(m[1])
	}
	for _, m := range reAxiosCall.FindAllStringSubmatch(js, -1) {
		add(m[2])
	}

	sort.Strings(out)
	return out
}

func extractMethodPaths(js string) []methodPath {
	seen := map[string]struct{}{}
	var out []methodPath

	add := func(method, p string) {
		method = strings.ToUpper(strings.TrimSpace(method))
		p = strings.TrimSpace(p)
		if method == "" || p == "" {
			return
		}
		if !looksInterestingPath(p) {
			return
		}
		key := method + "|" + p
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, methodPath{Method: method, Path: p})
	}

	for _, m := range reMethodPath.FindAllStringSubmatch(js, -1) {
		add(m[1], m[2])
	}
	for _, m := range reAxiosCall.FindAllStringSubmatch(js, -1) {
		add(m[1], m[2])
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Method < out[j].Method
		}
		return out[i].Path < out[j].Path
	})

	return out
}

func extractSecrets(js string) []secretCandidate {
	var out []secretCandidate

	add := func(kind, raw, severity, confidence string, evidence ...string) {
		out = append(out, secretCandidate{
			Kind:       kind,
			Redacted:   redact(raw),
			Severity:   severity,
			Confidence: confidence,
			Evidence:   evidence,
		})
	}

	for _, v := range reAWSAccessKey.FindAllString(js, -1) {
		add("aws_access_key_id", v, "medium", "medium", "AKIA_pattern")
	}
	for _, v := range reGoogleAPIKey.FindAllString(js, -1) {
		add("google_api_key", v, "info", "medium", "AIza_pattern")
	}
	for _, v := range reJWTLike.FindAllString(js, -1) {
		add("jwt_like", v, "medium", "low", "jwt_pattern")
	}
	for _, v := range reBearer.FindAllString(js, -1) {
		add("bearer_like", v, "medium", "low", "bearer_pattern")
	}
	for _, v := range reGenericSecret.FindAllString(js, -1) {
		add("generic_secret_pattern", v, "medium", "low", "generic_secret_pattern")
	}
	if rePrivateKey.MatchString(js) {
		add("private_key_block", "-----BEGIN ... PRIVATE KEY-----", "high", "high", "private_key_block")
	}
	if reFirebaseConfig.MatchString(js) && strings.Contains(strings.ToLower(js), "apikey") {
		add("firebase_config", "firebase_config_present", "info", "medium", "firebase_config")
	}

	return dedupeSecrets(out)
}

func looksInterestingPath(v string) bool {
	lv := strings.ToLower(v)
	for _, bad := range []string{
		".svg", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2",
		".ttf", ".css", ".ico", ".map",
	} {
		if strings.Contains(lv, bad) {
			return false
		}
	}
	if len(v) < 4 {
		return false
	}
	return strings.Contains(lv, "/api") ||
		strings.Contains(lv, "/admin") ||
		strings.Contains(lv, "/internal") ||
		strings.Contains(lv, "/debug") ||
		strings.Contains(lv, "/auth") ||
		strings.Contains(lv, "/graphql") ||
		strings.HasPrefix(v, "/") ||
		strings.HasPrefix(v, "http://") ||
		strings.HasPrefix(v, "https://")
}

func endpointEvidence(v string) []string {
	ev := []string{"path_in_js"}
	lv := strings.ToLower(v)
	for _, k := range []string{"/admin", "/internal", "/debug", "/auth", "/graphql", "/api"} {
		if strings.Contains(lv, k) {
			ev = append(ev, "keyword:"+k)
		}
	}
	return ev
}

func scoreEndpointSeverity(v string) string {
	lv := strings.ToLower(v)
	switch {
	case strings.Contains(lv, "/internal"),
		strings.Contains(lv, "/admin"),
		strings.Contains(lv, "/debug"):
		return "medium"
	case strings.Contains(lv, "/auth"),
		strings.Contains(lv, "/graphql"),
		strings.Contains(lv, "/api"):
		return "info"
	default:
		return "info"
	}
}

func redact(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 8 {
		return "redacted"
	}
	if strings.HasPrefix(v, "-----BEGIN") {
		return "-----BEGIN ... REDACTED -----"
	}
	return v[:4] + "..." + v[len(v)-4:]
}

func looksLikeJSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") || strings.Contains(p, ".js?") || strings.Contains(p, ".mjs?")
}

func isLikelyJS(body []byte) bool {
	lb := bytes.ToLower(body)
	return bytes.Contains(lb, []byte("function")) ||
		bytes.Contains(lb, []byte("const ")) ||
		bytes.Contains(lb, []byte("let ")) ||
		bytes.Contains(lb, []byte("webpack")) ||
		bytes.Contains(lb, []byte("sourcemappingurl"))
}

func dedupeSecrets(in []secretCandidate) []secretCandidate {
	seen := map[string]struct{}{}
	var out []secretCandidate
	for _, s := range in {
		key := s.Kind + "|" + s.Redacted
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}

func dedupeFindings(in []Finding) []Finding {
	seen := map[string]struct{}{}
	var out []Finding
	for _, f := range in {
		key := strings.Join([]string{
			f.Target,
			f.Asset,
			f.DiscoveredFrom,
			f.Finding,
			f.Framework,
			f.SourceMap,
			f.Endpoint,
			f.SecretType,
			f.ValueRedacted,
			strings.Join(f.Methods, ","),
			strings.Join(f.AuthHints, ","),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		f.SourcePaths = trimAndSortUnique(f.SourcePaths, 20)
		f.Evidence = trimAndSortUnique(f.Evidence, 50)
		f.Methods = trimAndSortUnique(f.Methods, 10)
		f.AuthHints = trimAndSortUnique(f.AuthHints, 20)
		out = append(out, f)
	}
	return out
}

func trimAndSortUnique(in []string, max int) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		return out[:max]
	}
	return out
}

func baseNameFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return path.Base(u.Path)
}
