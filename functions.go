package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
)

var (
	// StampLength # lenth stamp
	StampLength int64 = 12
	// LetterBytes random string generate
	LetterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

const (
	// LetterIdxBits num bits to represent a letter index
	LetterIdxBits = 6
	// LetterIdxMask All 1-bits, as many as letterIdxBits
	LetterIdxMask = 1<<LetterIdxBits - 1
	// LetterIdxMax # of letter indices fitting in 63 bits
	LetterIdxMax = 63 / LetterIdxBits
)

// GenerateRandomStringFixedLenght doc ...
func GenerateRandomStringFixedLenght(length, timestamp int64) string {
	src := rand.NewSource(timestamp)
	b := make([]byte, length)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := length-1, src.Int63(), LetterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), LetterIdxMax
		}
		if idx := int(cache & LetterIdxMask); idx < len(LetterBytes) {
			b[i] = LetterBytes[idx]
			i--
		}
		cache >>= LetterIdxMax
		remain--
	}
	return string(b)
}

// AESCbcDecrypter decrypt aes cipher strings
func AESCbcDecrypter(key, iv, ciphertext string) ([]byte, error) {
	cipherTextDecoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	// Decrypt string
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks([]byte(cipherTextDecoded), []byte(cipherTextDecoded))

	// Remove padding
	cipherDecrypted := unpad(cipherTextDecoded)
	return cipherDecrypted, nil
}

// AESCbcEncrypter encrypt strings to aes cipher strings
func AESCbcEncrypter(key, iv, s string) (string, error) {
	plaintext := []byte(s)
	// Add padding
	plaintext = pad(plaintext)
	if len(plaintext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks([]byte(ciphertext), plaintext)
	encrypted := hex.EncodeToString(ciphertext)
	return encrypted, nil
}

func generateSHA256Hash(s string) string {
	buf := []byte(s)
	h := sha256.New()
	h.Write(buf)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}
