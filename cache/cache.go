package cache

import (
	"fmt"
	"rrd-json-exporter/logger"
	"rrd-json-exporter/types"
	"sync"
	"time"
)

// listEntry is an rrd files name and expiration timestamp.
type listEntry struct {
	list       []byte
	expiration int64
}

// metricsEntry is a set of metrics and expiration timestamp.
type metricsEntry struct {
	metrics    []types.Metric
	expiration int64
}

var (
	listCache      = map[string]listEntry{}
	listCacheMutex sync.RWMutex
	ListTTL        int64 = 1800 // List TTL in seconds
)
var (
	metricsCache      = make(map[string]metricsEntry)
	metricsCacheMutex sync.RWMutex
	MetricsTTL        int64 = 300 // Metrics TTL in seconds
)

// GetListKey returns the cache key corresponding to the /list request.
func GetListKey(filter string, details bool) string {
	return fmt.Sprintf("list|%s|%t", filter, details)
}

// GetMetricsKey returns the cache key corresponding to the /metrics request.
func GetMetricsKey(path string, start, end int64) string {
	return fmt.Sprintf("%s|%d|%d", path, start, end)
}

// GetList returns cached RRD files list if still valid.
func GetList(key string) ([]byte, bool) {
	listCacheMutex.RLock()
	entry, ok := listCache[key]
	listCacheMutex.RUnlock()

	if !ok || time.Now().Unix() > entry.expiration {
		return nil, false
	}

	return entry.list, true
}

// GetMetrics returns cached metrics if still valid.
func GetMetrics(key string) ([]types.Metric, bool) {
	metricsCacheMutex.RLock()
	entry, ok := metricsCache[key]
	metricsCacheMutex.RUnlock()

	if !ok || time.Now().Unix() > entry.expiration {
		return nil, false
	}
	return entry.metrics, true
}

// SetList stores RRD files list in the cache.
func SetList(key string, list []byte) {
	listCacheMutex.Lock()
	listCache[key] = listEntry{
		list:       list,
		expiration: time.Now().Unix() + ListTTL,
	}
	listCacheMutex.Unlock()
}

// SetMetrics stores metrics in the cache.
func SetMetrics(key string, metrics []types.Metric) {
	metricsCacheMutex.Lock()
	metricsCache[key] = metricsEntry{
		metrics:    metrics,
		expiration: time.Now().Unix() + MetricsTTL,
	}
	metricsCacheMutex.Unlock()
}

// purgeCache purges expired keys from the cache.
func purgeCache[T any](cache map[string]T, cacheMutex *sync.RWMutex, expired func(T) bool) {
	cacheMutex.Lock()
	for key, entry := range cache {
		if expired(entry) {
			logger.Trace("Removing the cache key %s", key)
			delete(cache, key)
		}
	}
	cacheMutex.Unlock()
}

// StartCacheCleaner initializes regular cache cleaning.
func StartCacheCleaner() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			logger.Trace("Performing cache purge")
			now := time.Now().Unix()
			purgeCache(metricsCache, &metricsCacheMutex, func(e metricsEntry) bool { return e.expiration < now })
			purgeCache(listCache, &listCacheMutex, func(e listEntry) bool { return e.expiration < now })
		}
	}()
}
