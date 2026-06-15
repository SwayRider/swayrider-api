package handlers

import (
	"net/http"

	"github.com/swayrider/swayrider-api/api"
)

func OpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(api.Spec)
}
