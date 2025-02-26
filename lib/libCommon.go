package lib

import (
	cx "crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// GenRandString Function to generate random string based on the passed length
func GenRandomString(length int) (string, error) {
	if length < 1 {
		return "", errors.New("need length greator or equal to 1")
	}
	randomBytes := make([]byte, length)
	_, err := cx.Read(randomBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(randomBytes)[:length], nil
}

func HexDecode(txt string) []byte {
	x, _ := hex.DecodeString(txt)
	return x
}

func GenUlid() string {
	entropy := rand.New(rand.NewSource(time.Now().UnixNano()))
	ms := ulid.Timestamp(time.Now())
	u, _ := ulid.New(ms, entropy)
	return u.String()
}

func EncodeB64(message string) (retour string) {
	base64Text := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(base64Text, []byte(message))
	return string(base64Text)
}

func DecodeB64(message string) (retour string) {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	n, _ := base64.StdEncoding.Decode(base64Text, []byte(message))
	return string(base64Text[:n])
}

func GetSHA512Hash(txt string) string {
	h := sha512.New()
	h.Write([]byte(txt))
	sha := h.Sum(nil)
	return hex.EncodeToString(sha)
}
