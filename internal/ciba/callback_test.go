package ciba

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCallbackClient_Ping_PostsExpectedPayload(t *testing.T) {
	c := require.New(t)

	var captured PingPayload
	var headers http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cb := NewCallbackClient()
	c.NoError(cb.Ping(context.Background(), srv.URL, "rp-correlation-id", "auth-req-xyz"))

	c.Equal("auth-req-xyz", captured.AuthReqID)
	c.Equal("application/json", headers.Get("Content-Type"))
	c.Equal("Bearer rp-correlation-id", headers.Get("Authorization"))
}

func TestCallbackClient_Push_PostsFullTokenPayload(t *testing.T) {
	c := require.New(t)

	var captured PushPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cb := NewCallbackClient()
	c.NoError(cb.Push(context.Background(), srv.URL, "rp-correlation-id", PushPayload{
		AuthReqID:    "auth-req-xyz",
		AccessToken:  "acc",
		IDToken:      "idt",
		RefreshToken: "ref",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid profile",
	}))

	c.Equal("auth-req-xyz", captured.AuthReqID)
	c.Equal("acc", captured.AccessToken)
	c.Equal("idt", captured.IDToken)
	c.Equal("ref", captured.RefreshToken)
	c.Equal("Bearer", captured.TokenType)
	c.Equal(3600, captured.ExpiresIn)
	c.Equal("openid profile", captured.Scope)
}

func TestCallbackClient_OmitsAuthorizationWhenNoToken(t *testing.T) {
	c := require.New(t)

	var headers http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cb := NewCallbackClient()
	c.NoError(cb.Ping(context.Background(), srv.URL, "", "auth-req-xyz"))
	c.Empty(headers.Get("Authorization"))
}

func TestCallbackClient_NonTwoXX(t *testing.T) {
	c := require.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "RP rejected", http.StatusBadRequest)
	}))
	defer srv.Close()

	cb := NewCallbackClient()
	err := cb.Ping(context.Background(), srv.URL, "tok", "auth-req-xyz")
	c.ErrorIs(err, ErrCallbackNon2xx)
}

func TestCallbackClient_TransportError(t *testing.T) {
	c := require.New(t)

	cb := NewCallbackClient()
	err := cb.Ping(context.Background(), "http://127.0.0.1:1", "tok", "auth-req-xyz")
	c.ErrorIs(err, ErrCallbackTransport)
	c.NotErrorIs(err, ErrCallbackNon2xx)
}
