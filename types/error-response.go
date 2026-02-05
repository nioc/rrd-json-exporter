package types

// ErrorResponse represents an error.
type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Details any    `json:"details"`
}
