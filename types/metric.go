package types

// Metric represents a single datapoint extracted from an RRD file.
type Metric struct {
	Name      string  `json:"n"`
	Timestamp int64   `json:"t"`
	Value     float64 `json:"v"`
}
