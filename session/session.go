package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/blakewilliams/fernet"
)

type Verifier interface {
	Encode([]byte) (string, error)
	Decode(string) ([]byte, error)
}

// Sessionable is an interface that can be implemented by a RequestContext or
// other object to allow for easy access to the session.
type Sessionable[T any] interface {
	// SetSessionData sets the session data for the request.
	SetSessionData(T)
	// SessionData should return a pointer to the session data.
	SessionData() T

	fernet.RequestContext
}

// Middleware is a middleware function that can be used with the fernet
// middleware stack. It creates a new session and adds it to the RequestContext
// for the request.
func Middleware[RC Sessionable[T], T any](store Store[T]) func(ctx context.Context, rc RC, next fernet.Handler[RC]) {
	return func(ctx context.Context, rc RC, next fernet.Handler[RC]) {
		cookie, err := rc.Request().Cookie(store.Name)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			panic(err)
		}

		data, _ := store.FromCookie(cookie)
		originalData, err := store.FromCookie(cookie)
		if err != nil {
			panic(err)
		}

		rc.SetSessionData(data)

		defer func() {
			if !reflect.DeepEqual(originalData, data) {
				err = store.Write(rc, data)
				if err != nil {
					panic(err)
				}
			}
		}()

		next(ctx, rc)
	}
}

// Store is a wrapper around a http.Cookie that provides signed messages,
// allowing you to securely store data in a cookie.
//
// The data stored is still readable by the client, so secrets and sensitive
// data should not be stored in Store.Data.
type Store[T any] struct {
	verifier  Verifier
	Name      string
	initState func() T
}

// New creates a new Store with the given name and verifies Data using the
// passed in Verifier.
func New[T any](name string, verifier Verifier, initState func() T) Store[T] {
	return Store[T]{
		Name:      name,
		initState: initState,
		verifier:  verifier,
	}
}

// FromRequest reads the cookie with the provided name from the Request. The
// data is then decoded and verified using the Verifier.
func (s Store[T]) FromRequest(rc fernet.RequestContext) (T, error) {
	cookie, err := rc.Request().Cookie(s.Name)

	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		return s.initState(), fmt.Errorf("Could not create session from request: %w", err)
	}

	return s.FromCookie(cookie)
}

// FromCookie attempts to decode the data from the passed in Cookie and verifies
// the data hasn't been tampered with.
func (s Store[T]) FromCookie(cookie *http.Cookie) (T, error) {
	data := s.initState()
	if cookie == nil {
		return data, nil
	}

	decodedMessage, err := s.verifier.Decode(cookie.Value)

	if err != nil {
		return data, err
	}

	err = json.Unmarshal(decodedMessage, &data)

	if err != nil {
		return data, fmt.Errorf("Could not decode session: %w", err)
	}

	return data, nil
}

// Write encodes the Data into a JSON object, signs it using the message
// verifier, then writes it to the passed in fernet.RequestContext using the
// name provided by New.
func (s Store[T]) Write(rc fernet.RequestContext, data T) error {
	cookie, err := s.Cookie(data)
	if err != nil {
		return err
	}

	http.SetCookie(rc.Response(), cookie)

	return nil
}

// Cookie returns the underlying http.Cookie that is used to store the session.
func (s Store[T]) Cookie(data T) (*http.Cookie, error) {
	jsonValue, err := json.Marshal(data)

	if err != nil {
		return nil, fmt.Errorf("Could not marshal session data: %w", err)
	}

	encodedData, err := s.verifier.Encode(jsonValue)
	if err != nil {
		return nil, fmt.Errorf("could not encode data: %w", err)
	}

	return &http.Cookie{
		Name:  s.Name,
		Path:  "/",
		Value: string(encodedData),
	}, nil
}
