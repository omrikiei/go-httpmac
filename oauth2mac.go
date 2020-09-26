package oauth2mac

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	letterIdxBits    = 6                    // 6 bits to represent a letter index
	letterIdxMask    = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax     = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	letterBytes      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomStringSize = 8
	macDataPattern   = "%s\n%s\n%s\n%s\n%s\n%s\n%s"
)

var src = rand.NewSource(time.Now().UnixNano())

type MacAuthenticator struct {
	Id         string
	Secret     string
	Issued     time.Time
	Alg        crypto.Hash
	algExec    hash.Hash
	minimumAge int64
}

type MacHeader struct {
	Id    string
	Nonce string
	Hash  []byte
	Ext   string
}

func NewMacHeader(id, nonce string, hash []byte, ext string) *MacHeader {
	return &MacHeader{
		id,
		nonce,
		hash,
		ext,
	}
}

func NewMacHeaderFromRequest(request *http.Request) (*MacHeader, error) {
	m := MacHeader{}
	authHeader := request.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "mac ") {
		return nil, errors.New("auth header is not of type 'mac'")
	}

	authHeader = strings.TrimPrefix(authHeader, "mac ")
	splitHeader := strings.Split(authHeader, "\n")
	for _, pair := range splitHeader {
		splitPair := strings.SplitN(pair, "=", 1)
		if len(splitPair) != 2 || !strings.HasPrefix(splitPair[1], "\"") || !strings.HasPrefix(splitPair[1], "\n"){
			return nil, errors.New("bad auth header format")
		}
		key := splitPair[0]
		value := splitPair[1][1:len(splitPair[1]) - 2]
		if key == "id" {
			m.Id = value
		} else if key == "nonce" {
			m.Nonce = value
		} else if key == "hash" {
			h, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return nil, errors.New("bad auth header mac format")
			}
			m.Hash = h
		} else if key == "ext" {
			m.Ext = value
		} else {
			return nil, errors.New("bad auth header format")
		}
	}

	return &m, nil
}

func (m MacHeader) String() string {
	header := fmt.Sprintf("mac id=\"%s\"\nnonce=\"%s\"\nhash=\"%s\"", m.Id, m.Nonce, base64.StdEncoding.EncodeToString(m.Hash))
	if m.Ext != "" {
		header = fmt.Sprintf("%s\next=\"%s\"", header, m.Ext)
	}
	return header
}

func NewMacAuthenticator(id, secret string, issued time.Time, algorithm crypto.Hash) *MacAuthenticator {
	return &MacAuthenticator{
		id,
		secret,
		issued,
		algorithm,
		algorithm.New(),
		int64(time.Now().UTC().Sub(issued).Seconds()),
	}
}

func (m MacAuthenticator) Sign(request *http.Request, ext string) error {
	age := int64(time.Now().UTC().Sub(m.Issued).Seconds())
	randomString := getRandomString(randomStringSize)
	nonce := fmt.Sprintf("%d:%s", age, randomString)
	macHash, err := m.calculateHash(request, nonce, ext)
	if err != nil {
		return err
	}
	macHeader := NewMacHeader(m.Id, nonce, macHash, ext)
	request.Header.Add("Authorization", macHeader.String())
	return nil
}

func (m *MacAuthenticator) Verify(w http.ResponseWriter, request *http.Request) error {
	macHeader, err := NewMacHeaderFromRequest(request)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("WWW-Authenticate", "MAC")
		return err
	}
	age, err := strconv.ParseInt(strings.Split(macHeader.Nonce, ":")[0], 10, 64)
	if err != nil || age < m.minimumAge {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("WWW-Authenticate", "MAC")
		return err
	}
	calculatedHash, err := m.calculateHash(request, macHeader.Nonce, macHeader.Ext)
	if bytes.Compare(calculatedHash, macHeader.Hash) == 0 {
		m.minimumAge = age
		return nil
	}
	w.WriteHeader(http.StatusUnauthorized)
	return errors.New("unauthorized")
}

func (m *MacAuthenticator) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := m.Verify(w, r)
		if err != nil {
			return
		}
		next(w, r)
	}
}

func (m MacAuthenticator) calculateHash(request *http.Request, nonce string, ext string) ([]byte, error) {
	bodyHash, err := m.getBodyHash(request)
	if err != nil {
		return []byte{}, err
	}
	port := getPort(request)
	m.algExec.Write([]byte(fmt.Sprintf(macDataPattern, nonce, request.Method, request.RequestURI, request.Host, port, bodyHash, ext)))
	defer m.algExec.Reset()
	macHash := m.algExec.Sum(nil)
	return macHash, nil
}

func (m MacAuthenticator) getBodyHash(r *http.Request) (string, error) {
	requestBody, err := r.GetBody()
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(requestBody)
	if err != nil {
		return "", err
	}
	body := buf.Bytes()
	hashResult := m.algExec.Sum(body)
	return base64.StdEncoding.EncodeToString(hashResult), nil
}

func getPort(r *http.Request) string {
	splitHost := strings.Split(r.Host, ":")
	if len(splitHost) == 3 {
		return splitHost[2]
	}

	if len(splitHost) == 2 && strings.ToLower(splitHost[0]) == "https" {
		return "443"
	}

	return "80"
}

func getRandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}
