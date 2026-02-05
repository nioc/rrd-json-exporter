package types

// RRDInfo describes an RRD file created by Munin.
type RRDInfo struct {
	Nodename string `json:"nodename"`
	Plugin   string `json:"plugin"`
	Field    string `json:"field"`
	Type     string `json:"type"`
	Name     string `json:"name"`
}
