package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var logLevel string

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

// CacheEntry stores metrics and expiration timestamp.
type CacheEntry struct {
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
	cache      = make(map[string]CacheEntry)
	cacheMutex sync.RWMutex
	cacheTTL   int64 = 60 // default TTL in seconds
)

// Logging helpers
func logDebug(msg string, args ...any) {
	if logLevel == "debug" {
		log.Printf("[DEBUG] "+msg, args...)
	}
}

func logInfo(msg string, args ...any) {
	if logLevel == "info" || logLevel == "debug" {
		log.Printf("[INFO] "+msg, args...)
	}
}

func logError(msg string, args ...any) {
	if logLevel == "error" || logLevel == "info" || logLevel == "debug" {
		log.Printf("[ERROR] "+msg, args...)
	}
}

func logFatal(msg string, args ...any) {
	log.Fatalf("[FATAL] "+msg, args...)
}

// writeJSONError sends a structured JSON error response and logs it.
func writeJSONError(w http.ResponseWriter, status int, message string, details any) {
	logError("%s | details: %v", message, details)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(ErrorResponse{"error", message, details})
}

// Caching functions
// getFromCache returns cached metrics if still valid.
func getFromCache(key string) ([]Metric, bool) {
	cacheMutex.RLock()
	entry, ok := cache[key]
	cacheMutex.RUnlock()

	if !ok || time.Now().Unix() > entry.Expiration {
		return nil, false
	}
	return entry.Metrics, true
}

// setCache stores metrics in the cache.
func setCache(key string, metrics []Metric) {
	cacheMutex.Lock()
	cache[key] = CacheEntry{
		Metrics:    metrics,
		Expiration: time.Now().Unix() + cacheTTL,
	}
	cacheMutex.Unlock()
}

// readRRD executes "rrdtool fetch" and parses the output into metrics.
func readRRD(path string, name string) ([]Metric, error) {
	cmd := exec.Command("rrdtool", "fetch", path, "AVERAGE")
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
	logDebug("HTTP %s %s?%s from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
	files, err := os.ReadDir("rrd")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "RRD directory read error", err.Error())
		return
	}

	filter := r.URL.Query().Get("filter")
	isDetailled := r.URL.Query().Has("details")
	var re *regexp.Regexp
	if filter != "" {
		// Check the provided regex
		re, err = compileRegexSafe(filter, 10*time.Millisecond)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid or unsafe regex", err.Error())
			return
		}
	}

	names := []string{}
	for _, file := range files {
		name := file.Name()

		// Keep only rrd files matching the regex (if provided)
		if strings.HasSuffix(name, ".rrd") && (re == nil || re.MatchString(name)) {
			names = append(names, name)
		}
	}

	w.Header().Set("Content-Type", "application/json")
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
		json.NewEncoder(w).Encode(namesWithDetails)
	} else {
		json.NewEncoder(w).Encode(names)
	}
}

// Returns metrics from one or all RRD files.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	logDebug("HTTP %s %s?%s from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
	fileParam := r.URL.Query().Get("rrd")

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
				writeJSONError(w, http.StatusNotFound, "RRD file not found", file)
				return
			}
			files = append(files, full)
		}
	}

	var all []Metric

	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".rrd")
		// Try cache first
		if cached, ok := getFromCache(f); ok {
			logDebug("Cache hit for %s", f)
			all = append(all, cached...)
			continue
		}

		logDebug("Cache miss for %s", f)

		metrics, err := readRRD(f, name)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "RRD files reading error", err.Error())
			return
		}
		if len(metrics) == 0 {
			writeJSONError(w, http.StatusNotFound, "No data found in RRD file", filepath.Base(f))
			return
		}

		setCache(f, metrics)
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
	logLevel = strings.ToLower(os.Getenv("LOG_LEVEL"))
	if logLevel == "" {
		logLevel = "info"
	}

	// Get cache TTL
	if ttlStr := os.Getenv("CACHE_TTL"); ttlStr != "" {
		if ttl, err := strconv.ParseInt(ttlStr, 10, 64); err == nil && ttl > 0 {
			cacheTTL = ttl
			logInfo("Cache TTL set to %d seconds", cacheTTL)
		} else {
			logError("Invalid CACHE_TTL value: %s", ttlStr)
		}
	}

	// Check rrdtool
	if _, err := exec.LookPath("rrdtool"); err != nil {
		logFatal("rrdtool not found in PATH")
	}

	http.HandleFunc("/health", healthHandler)

	http.HandleFunc("/list", basicAuth(listHandler))

	http.HandleFunc("/metrics", basicAuth(metricsHandler))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logError("HTTP %s %s?%s (404) from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
	})

	logInfo("RRD Exporter running on port %s", port)

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		logFatal("Server stopped %v", err)
	}

}
