package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenRandString(t *testing.T) {
	s, err := GenRandomString(48)
	require.NoError(t, err, "Should not throw error but got error")
	require.Len(t, s, 48, "should be a 48 chars but got less or greator then 48")

	s2, err2 := GenRandomString(0)
	require.Error(t, err2, "Should throw error but got no error")
	require.Len(t, s2, 0, "should be a 0 chars but got less or greator then 0")
}

func TestGenUlid(t *testing.T) {
	u := GenUlid()

	require.NotEmpty(t, u)
	require.Len(t, u, 26)
}

func TestEncodeB64(t *testing.T) {
	text := "Hello world!"
	encodedText := "SGVsbG8gd29ybGQh"
	myEncode := EncodeB64(text)

	require.NotEmpty(t, myEncode)
	require.Equal(t, encodedText, myEncode)
}

func TestDecodeB64(t *testing.T) {
	text := "Hello world!"
	encodedText := "SGVsbG8gd29ybGQh"
	myDecode := DecodeB64(encodedText)

	require.NotEmpty(t, myDecode)
	require.Equal(t, text, myDecode)
}

func TestGetSHA512Hash(t *testing.T) {
	txt := "Hello World!"
	actualSum := "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
	mySum := GetSHA512Hash(txt)
	require.NotEmpty(t, mySum)
	require.Equal(t, actualSum, mySum)
}
