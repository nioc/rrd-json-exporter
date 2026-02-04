package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"rrd-json-exporter/logger"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RRDInfo describes an RRD file created by Munin.
type RRDInfo struct {
	Nodename string `json:"nodename"`
	Plugin   string `json:"plugin"`
	Field    string `json:"field"`
	Type     string `json:"type"`
	Name     string `json:"name"`
}

// Metric represents a single datapoint extracted from an RRD file.
type Metric struct {
	Name      string  `json:"n"`
	Timestamp int64   `json:"t"`
	Value     float64 `json:"v"`
}

// ListCacheEntry stores rrd files name and expiration timestamp.
type ListCacheEntry struct {
	List       []byte
	Expiration int64
}

// MetricsCacheEntry stores metrics and expiration timestamp.
type MetricsCacheEntry struct {
	Metrics    []Metric
	Expiration int64
}

// ErrorResponse represents an error.
type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Details any    `json:"details"`
}

var (
	listCache      = map[string]ListCacheEntry{}
	listCacheMutex sync.RWMutex
	listCacheTTL   int64 = 1800 // default TTL in seconds
)
var (
	metricsCache      = make(map[string]MetricsCacheEntry)
	metricsCacheMutex sync.RWMutex
	metricsCacheTTL   int64 = 60 // default TTL in seconds
)

// Default rounding "from" and "to" timestamps to 300 seconds (5 minutes)
var roundStep = int64(300)

// writeJSONError sends a structured JSON error response and logs it.
func writeJSONError(w http.ResponseWriter, status int, message string, details any) {
	logger.Error("%s | details: %v", message, details)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(ErrorResponse{"error", message, details})
}

// Caching functions

// getListCacheKey returns the cache key corresponding to the /list request.
func getListCacheKey(filter string, details bool) string {
	return fmt.Sprintf("list|%s|%t", filter, details)
}

// getMetricsCacheKey returns the cache key corresponding to the request.
func getMetricsCacheKey(path string, start, end int64) string {
	return fmt.Sprintf("%s|%d|%d", path, start, end)
}

// getListFromCache returns cached RRD files list if still valid.
func getListFromCache(key string) ([]byte, bool) {
	listCacheMutex.RLock()
	entry, ok := listCache[key]
	listCacheMutex.RUnlock()

	if !ok || time.Now().Unix() > entry.Expiration {
		return nil, false
	}

	return entry.List, true
}

// getMetricsFromCache returns cached metrics if still valid.
func getMetricsFromCache(key string) ([]Metric, bool) {
	metricsCacheMutex.RLock()
	entry, ok := metricsCache[key]
	metricsCacheMutex.RUnlock()

	if !ok || time.Now().Unix() > entry.Expiration {
		return nil, false
	}
	return entry.Metrics, true
}

// setListCache stores RRD files list in the cache.
func setListCache(key string, list []byte) {
	listCacheMutex.Lock()
	listCache[key] = ListCacheEntry{
		List:       list,
		Expiration: time.Now().Unix() + listCacheTTL,
	}
	listCacheMutex.Unlock()
}

// setMetricsCache stores metrics in the cache.
func setMetricsCache(key string, metrics []Metric) {
	metricsCacheMutex.Lock()
	metricsCache[key] = MetricsCacheEntry{
		Metrics:    metrics,
		Expiration: time.Now().Unix() + metricsCacheTTL,
	}
	metricsCacheMutex.Unlock()
}

// getTtl reads environment variable and returns its value.
func getTtl(key string) (int64, bool) {
	if ttlStr := os.Getenv(key); ttlStr != "" {
		if ttl, err := strconv.ParseInt(ttlStr, 10, 64); err == nil && ttl > 0 {
			return ttl, true
		} else {
			logger.Error("Invalid %s value: %s", key, ttlStr)
		}
	}
	return 0, false
}

// startCacheCleaner initializes regular cache cleaning.
func startCacheCleaner() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			logger.Trace("Performing cache purge")
			now := time.Now().Unix()

			metricsCacheMutex.Lock()
			for key, entry := range metricsCache {
				if entry.Expiration < now {
					logger.Trace("Removing the metrics cache key %s", key)
					delete(metricsCache, key)
				}
			}
			metricsCacheMutex.Unlock()

			listCacheMutex.Lock()
			for key, entry := range listCache {
				if entry.Expiration < now {
					logger.Trace("Removing the list cache key %s", key)
					delete(listCache, key)
				}
			}
			listCacheMutex.Unlock()
		}
	}()
}

// readRRD executes "rrdtool fetch" and parses the output into metrics.
func readRRD(path string, name string, start, end int64) ([]Metric, error) {
	args := []string{"fetch", path, "AVERAGE"}
	if start > 0 {
		args = append(args, "--start", strconv.FormatInt(start, 10))
	}
	if end > 0 {
		args = append(args, "--end", strconv.FormatInt(end, 10))
	}
	logger.Trace("Cmd: rrdtool %s", strings.Join(args, " "))
	cmd := exec.Command("rrdtool", args...)
	cmd.Env = append(os.Environ(), "LC_NUMERIC=C")

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rrdtool error: %w", err)
	}

	lines := bytes.Split(out, []byte{'\n'})
	var metrics []Metric

	// Ignore first 2 lines (headers)
	for _, line := range lines[2:] {
		fields := bytes.Fields(line)
		if len(fields) != 2 {
			continue
		}

		// Get timestamp
		tsBytes := bytes.TrimSuffix(fields[0], []byte{':'})
		ts, err := strconv.ParseInt(string(tsBytes), 10, 64)
		if err != nil {
			continue
		}

		// Get value
		valBytes := bytes.ReplaceAll(fields[1], []byte(","), []byte("."))
		if bytes.Contains(valBytes, []byte("nan")) {
			continue
		}

		val, err := strconv.ParseFloat(string(valBytes), 64)
		if err != nil {
			continue
		}

		metrics = append(metrics, Metric{
			Name:      name,
			Timestamp: ts,
			Value:     val,
		})
	}
	logger.Trace("Found %d values in %s", len(metrics), name)

	return metrics, nil
}

var validRRD = regexp.MustCompile(`^[a-zA-Z0-9._-]+\.rrd$`)

// validateRRDFile ensures the filename is safe and allowed.
func validateRRDFile(name string) bool {
	if strings.ContainsAny(name, "/\\") {
		return false
	}
	return validRRD.MatchString(name)
}

// Check Authorization
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	user := os.Getenv("AUTH_USER")
	pass := os.Getenv("AUTH_PASS")

	// Si pas configuré → pas d’auth
	if user == "" || pass == "" {
		return next
	}

	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized", nil)
			return
		}
		next(w, r)
	}
}

// Verifies that the regular expression compiles within a timeout while checking backtracking
func compileRegexSafe(pattern string, timeout time.Duration) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Check backtracking
	done := make(chan struct{})
	go func() {
		re.MatchString("")
		close(done)
	}()

	// Handle timeout
	select {
	case <-done:
		return re, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("regex evaluation timed out")
	}
}

// Parses the name of the rrd file created by munin to provide information about it.
func parseRRDName(filename string) (*RRDInfo, error) {
	if !strings.HasSuffix(filename, ".rrd") {
		return nil, fmt.Errorf("not an rrd file")
	}

	base := strings.TrimSuffix(filename, ".rrd")
	parts := strings.Split(base, "-")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid rrd filename format")
	}

	nodename := parts[0]
	plugin := parts[1]
	// handles fields with hyphens
	field := strings.Join(parts[2:len(parts)-1], "-")
	rrdType := parts[len(parts)-1]

	var typeName string
	switch rrdType {
	case "g":
		typeName = "gauge"
	case "d":
		typeName = "derive"
	case "a":
		typeName = "absolute"
	case "c":
		typeName = "counter"
	default:
		typeName = rrdType
	}

	return &RRDInfo{
		Nodename: nodename,
		Plugin:   plugin,
		Field:    field,
		Type:     typeName,
		Name:     filename,
	}, nil
}

// Converts a timestamp string in milliseconds to an integer in seconds.
func getTimestamp(tsStr string, isFrom bool) int64 {
	if tsStr != "" {
		tsMs, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			name := "to"
			if isFrom {
				name = "from"
			}
			logger.Error("Invalid \"%s\" value %s, error: %v", name, tsStr, err.Error())
		} else {
			var sec int64 = tsMs / 1000
			if isFrom {
				return (sec / roundStep) * roundStep
			} else {
				return ((sec + roundStep - 1) / roundStep) * roundStep
			}
		}
	}
	return 0
}

// Returns a simple OK status for container health checks.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

// Returns the list of available RRD files.
func listHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debug("HTTP %s %s?%s from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)

	filter := r.URL.Query().Get("filter")
	isDetailled := r.URL.Query().Has("details")
	key := getListCacheKey(filter, isDetailled)

	w.Header().Set("Content-Type", "application/json")

	// Try cache first
	if list, ok := getListFromCache(key); ok {
		logger.Trace("Cache hit for /list key=%s", key)
		w.Write(list)
		return
	}

	logger.Trace("Cache miss for /list key=%s", key)

	files, err := os.ReadDir("rrd")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "RRD directory read error", err.Error())
		return
	}

	var re *regexp.Regexp
	if filter != "" {
		// Check the provided regex
		re, err = compileRegexSafe(filter, 10*time.Millisecond)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid or unsafe regex", err.Error())
			return
		}
	}

	names := make([]string, 0, len(files))
	for _, file := range files {
		name := file.Name()

		// Keep only rrd files matching the regex (if provided)
		if strings.HasSuffix(name, ".rrd") && (re == nil || re.MatchString(name)) {
			names = append(names, name)
		}
	}

	var list []byte
	if isDetailled {
		namesWithDetails := make([]RRDInfo, 0, len(names))
		for _, name := range names {
			info, err := parseRRDName(name)
			if err != nil {
				namesWithDetails = append(namesWithDetails, RRDInfo{
					Nodename: "?",
					Plugin:   "?",
					Field:    "?",
					Type:     "?",
					Name:     name,
				})
				continue
			}
			namesWithDetails = append(namesWithDetails, *info)
		}
		list, err = json.Marshal(namesWithDetails)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "JSON encoding error", err.Error())
			return
		}
	} else {
		list, err = json.Marshal(names)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "JSON encoding error", err.Error())
			return
		}
	}
	setListCache(key, list)
	w.Write(list)
}

// Returns metrics from one or all RRD files.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debug("HTTP %s %s?%s from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
	fileParam := r.URL.Query().Get("rrd")

	// Get time range (expected in ms)
	start := getTimestamp(r.URL.Query().Get("from"), true)
	end := getTimestamp(r.URL.Query().Get("to"), false)

	var files []string

	if fileParam == "" {
		// No `file` was provided, read all files
		var err error
		files, err = filepath.Glob("rrd/*.rrd")
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "RRD directory read error", err.Error())
			return
		}
		if len(files) == 0 {
			writeJSONError(w, http.StatusNotFound, "No RRD files found", nil)
			return
		}
		if len(files) > 100 {
			writeJSONError(w, http.StatusBadRequest, "Too many RRD files", len(files))
			return
		}
	} else {
		// A `file` parameter was provided, try to read it
		// Grafana multi-value: {file1,file2,file3}
		cleaned := strings.Trim(fileParam, " {}")

		// Split multi-values
		parts := strings.SplitSeq(cleaned, ",")

		for file := range parts {
			file = strings.TrimSpace(file)

			if !validateRRDFile(file) {
				writeJSONError(w, http.StatusBadRequest, "Invalid filename", file)
				return
			}
			full := filepath.Join("rrd", file)
			if _, err := os.Stat(full); err != nil {
				logger.Error("RRD file %s not found", file)
				continue
			}
			files = append(files, full)
		}
	}

	var all []Metric

	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".rrd")
		// Try cache first
		key := getMetricsCacheKey(file, start, end)
		if cached, ok := getMetricsFromCache(key); ok {
			logger.Trace("Cache hit for %s", key)
			all = append(all, cached...)
			continue
		}

		logger.Trace("Cache miss for %s", key)

		metrics, err := readRRD(file, name, start, end)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "RRD files reading error", err.Error())
			return
		}
		if len(metrics) == 0 {
			logger.Error("No data found in %s RRD file", filepath.Base(file))
			continue
		}

		setMetricsCache(key, metrics)
		all = append(all, metrics...)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(all)
}

func main() {
	// Get listening port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Get log level
	logLevel := os.Getenv("LOG_LEVEL")
	logger.SetLevel(logLevel)

	// Check rrdtool
	if _, err := exec.LookPath("rrdtool"); err != nil {
		logger.Fatal("rrdtool not found in PATH")
	}

	// Get round step
	if roundStepStr := os.Getenv("ROUND_STEP"); roundStepStr != "" {
		if rs, err := strconv.ParseInt(roundStepStr, 10, 64); err == nil && rs > 0 {
			roundStep = rs
			logger.Info("Rounding step (from and to timestamps) set to %d seconds", roundStep)
		} else {
			logger.Error("Invalid ROUND_STEP value: %s", roundStepStr)
		}
	}

	// Get cache TTL
	if ttl, ok := getTtl("CACHE_TTL_METRICS"); ok {
		metricsCacheTTL = ttl
	}
	logger.Info("Metrics cache TTL set to %d seconds", metricsCacheTTL)

	if ttl, ok := getTtl("CACHE_TTL_LIST"); ok {
		listCacheTTL = ttl
	}
	logger.Info("List cache TTL set to %d seconds", listCacheTTL)

	http.HandleFunc("/health", healthHandler)

	http.HandleFunc("/list", basicAuth(listHandler))

	http.HandleFunc("/metrics", basicAuth(metricsHandler))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Error("HTTP %s %s?%s (404) from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
	})

	logger.Info("RRD JSON Exporter running on port %s", port)

	startCacheCleaner()

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		logger.Fatal("Server stopped %v", err)
	}

}
