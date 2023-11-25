package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blakewilliams/fernet"
	"github.com/stretchr/testify/require"
)

type MyData struct {
	UserID int
	Name   string
}

func TestStoreCookie(t *testing.T) {
	verifier := NewVerifier("TheTruthIsOutThere")
	router := fernet.New(func(rc fernet.RequestContext) fernet.RequestContext { return rc })

	router.Get("/", func(ctx context.Context, rc fernet.RequestContext) {
		session := New[MyData]("session", verifier)
		err := session.FromRequest(rc)
		require.NoError(t, err)

		session.Data.UserID = 500
		session.Data.Name = "Fox Mulder"

		err = session.Write(rc)
		require.NoError(t, err)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	cookie := res.Result().Cookies()
	session := New[MyData]("session", verifier)
	err := session.FromCookie(cookie[0])

	require.NoError(t, err)
	require.Equal(t, "Fox Mulder", session.Data.Name)
	require.Equal(t, 500, session.Data.UserID)
}
func TestStoreCookie_WriteIfChanged(t *testing.T) {
	verifier := NewVerifier("TheTruthIsOutThere")

	router := fernet.New(func(rc fernet.RequestContext) fernet.RequestContext { return rc })
	router.Get("/", func(ctx context.Context, rc fernet.RequestContext) {
		session := New[MyData]("session", verifier)
		err := session.FromRequest(rc)
		require.NoError(t, err)

		session.Data.UserID = 500
		session.Data.Name = "Fox Mulder"

		err = session.WriteIfChanged(rc)
		require.NoError(t, err)
	})

	// Should set cookie since no cookies are set
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	setCookie := res.Result().Header.Get("Set-Cookie")
	require.NotEmpty(t, setCookie)

	// Second request should not have cookie set, since nothing has changed.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", setCookie)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	setCookie = res.Result().Header.Get("Set-Cookie")
	require.Empty(t, setCookie)
}
