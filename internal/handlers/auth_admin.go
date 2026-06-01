package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/swayrider/grpcclients/authclient"
	"github.com/swayrider/swlib/security"
)

func (h *AuthHandler) CreateAdmin(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	userId, message, err := h.client.CreateAdmin(token, req.Email, req.Password)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"user_id": userId,
		"message": message,
	})
}

func (h *AuthHandler) ChangeAccountType(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		UserId      string `json:"userId"`
		AccountType string `json:"accountType"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	message, err := h.client.ChangeAccountType(token, req.UserId, req.AccountType)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": message})
}

func (h *AuthHandler) WhoIs(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Email  string `json:"email"`
		UserId string `json:"userId"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	var lookup authclient.WhoIsOneOf
	switch {
	case req.Email != "":
		lookup = authclient.WhoIs_Email(req.Email)
	case req.UserId != "":
		lookup = authclient.WhoIs_UserId(req.UserId)
	default:
		http.Error(w, "email or userId required", http.StatusBadRequest)
		return
	}
	user, err := h.client.WhoIs(token, lookup, func(userId, email string, isVerified, isAdmin bool, accountType string) authclient.User {
		return whoAmIUser{userId, email, isVerified, isAdmin, accountType}
	})
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":      user.UserId(),
		"email":        user.Email(),
		"is_verified":  user.IsVerified(),
		"is_admin":     user.IsAdmin(),
		"account_type": user.AccountType(),
	})
}

func (h *AuthHandler) InviteUser(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	message, err := h.client.InviteUser(token, req.Email)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": message})
}

func (h *AuthHandler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	message, err := h.client.RevokeInvite(token, req.Email)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": message})
}

func (h *AuthHandler) ListInvites(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if pageSize < 1 {
		pageSize = 20
	}
	var registered *bool
	if raw := r.URL.Query().Get("registered"); raw != "" {
		v := raw == "true"
		registered = &v
	}
	invites, total, err := h.client.ListInvites(token, page, pageSize, registered, func(id, email string, createdAt time.Time, reg bool) authclient.Invite {
		return inviteResult{id, email, createdAt, reg}
	})
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	out := make([]map[string]any, len(invites))
	for i, inv := range invites {
		out[i] = map[string]any{
			"id":         inv.Id(),
			"email":      inv.Email(),
			"created_at": inv.CreatedAt(),
			"registered": inv.Registered(),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"invites":     out,
		"num_invites": total,
	})
}

func (h *AuthHandler) CreateServiceClient(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Scopes      []string `json:"scopes"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	clientId, clientSecret, err := h.client.CreateServiceClient(token, req.Name, req.Description, req.Scopes)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"client_id":     clientId,
		"client_secret": clientSecret,
	})
}

func (h *AuthHandler) DeleteServiceClient(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		ClientId string `json:"clientId"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	message, err := h.client.DeleteServiceClient(token, req.ClientId)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": message})
}

func (h *AuthHandler) ListServiceClients(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if pageSize < 1 {
		pageSize = 20
	}
	clients, total, err := h.client.ListServiceClients(token, page, pageSize, func(clientId, name, description string, scopes ...string) authclient.ServiceClient {
		return serviceClientResult{clientId, name, description, scopes}
	})
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	out := make([]map[string]any, len(clients))
	for i, c := range clients {
		out[i] = map[string]any{
			"client_id":   c.ClientId(),
			"name":        c.Name(),
			"description": c.Description(),
			"scopes":      c.Scopes(),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"clients":     out,
		"num_clients": total,
	})
}

// --- private result types ---

type inviteResult struct {
	id         string
	email      string
	createdAt  time.Time
	registered bool
}

func (i inviteResult) Id() string           { return i.id }
func (i inviteResult) Email() string        { return i.email }
func (i inviteResult) CreatedAt() time.Time { return i.createdAt }
func (i inviteResult) Registered() bool     { return i.registered }

type serviceClientResult struct {
	clientId    string
	name        string
	description string
	scopes      []string
}

func (s serviceClientResult) ClientId() string    { return s.clientId }
func (s serviceClientResult) Name() string        { return s.name }
func (s serviceClientResult) Description() string { return s.description }
func (s serviceClientResult) Scopes() []string    { return s.scopes }
