package oauth2mac

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewMacAuthenticator(t *testing.T) {

}

func TestMacAuthenticator_Sign(t *testing.T) {
	mauth := NewMacAuthenticator(
		"h480djs93hd8",
		"489dks293j39",
		time.Date(2010, 12, 02, 21, 35, 45, 0, time.UTC),
		crypto.SHA1,
	)

	r, _ := http.NewRequest(http.MethodGet, "http://www.example.com/resource/1?b=1&a=2", bytes.NewReader([]byte{}))

	err := mauth.Sign(r, "")
	if err != nil {
		t.Error(err)
	}

	// Header consists of 3 segments
	authHeader := r.Header.Get("Authorization")
	splitHeader := strings.Split(authHeader, "\n")
	if len(splitHeader) != 3 {
		t.Error("Incorrect number of header attributes")
	}
	// Hash is base64
	hashValue := strings.Split(splitHeader[2], "\"")[1]
	_, err = base64.StdEncoding.DecodeString(hashValue)
	if err != nil {
		t.Error(err)
	}
}

func TestMacAuthenticator_Verify(t *testing.T) {

}
