package main

import (
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

// Metric represents a single datapoint extracted from an RRD file.
type Metric struct {
	Name      string  `json:"name"`
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

// Response wraps a list of metrics for JSON output.
type Response struct {
	Metrics []Metric `json:"metrics"`
}

// cacheEntry stores metrics and expiration timestamp.
type cacheEntry struct {
	Metrics    []Metric
	Expiration int64
}

var (
	cache      = make(map[string]cacheEntry)
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

	json.NewEncoder(w).Encode(map[string]any{
		"status":  "error",
		"message": message,
		"details": details,
	})
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
	cache[key] = cacheEntry{
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

	lines := strings.Split(string(out), "\n")
	var metrics []Metric

	// Ignore first 2 lines (headers)
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}

		// Get timestamp
		tsStr := strings.TrimSuffix(fields[0], ":")
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			continue
		}

		// Get value
		valStr := strings.ReplaceAll(fields[1], ",", ".")
		if strings.Contains(valStr, "nan") {
			continue
		}

		val, err := strconv.ParseFloat(valStr, 64)
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

	// healthHandler returns a simple OK status for container health checks.
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
	})

	// Returns the list of available RRD files.
	http.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		logDebug("HTTP %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		files, err := filepath.Glob("rrd/*.rrd")
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "RRD directory read error", err.Error())
			return
		}

		var names []string
		for _, f := range files {
			names = append(names, filepath.Base(f))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(names)
	})

	// Returns metrics from one or all RRD files.
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
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
			cleaned := strings.TrimSpace(fileParam)
			cleaned = strings.TrimPrefix(cleaned, "{")
			cleaned = strings.TrimSuffix(cleaned, "}")

			// Split multi-values
			parts := strings.Split(cleaned, ",")

			for _, file := range parts {
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
		json.NewEncoder(w).Encode(Response{Metrics: all})
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logError("HTTP %s %s?%s (404) from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
	})

	logInfo("RRD Exporter running on port %s", port)

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		logFatal("Server stopped %v", err)
	}

}
