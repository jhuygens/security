package security

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jgolang/config"
	"github.com/jgolang/log"
	"golang.org/x/crypto/bcrypt"
)

const (
	secretKeyLayout = "%v;%v;%v;%v;%v"
	clientIDLayout  = "user:%v,timestamp:%v,stamp:%v"
	tokenLayout     = "%v;%v;%v;%v"
	stampLayout     = "X1%vD-E%v#1%v"
)

// GenerateSecurePassword generate bcrypt password
func GenerateSecurePassword(password string) (string, error) {
	cost := config.GetInt("general.password_secure_cost")
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(bytes), err
}

// ValidateSecurePassword validate user password
func ValidateSecurePassword(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil, err
}

// GenerateSecretKey generate SHA-256 hash string
// expire in seconds
func GenerateSecretKey(email, clientID, password string, expire int) (string, error) {
	timestamp := time.Now().UnixNano()
	stamp := GenerateRandomStringFixedLenght(StampLength, timestamp)
	s := fmt.Sprintf(secretKeyLayout, email, clientID, timestamp, stamp, expire)
	iv := config.GetString("general.secure_secret_iv")
	key := config.GetString("general.secure_secret_key")
	hash, err := AESCbcEncrypter(key, iv, s)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// ValidateSecretKey validate secret key
func ValidateSecretKey(secretKey string) (bool, error) {
	iv := config.GetString("general.secure_secret_iv")
	key := config.GetString("general.secure_secret_key")
	decriptedSecretKey, err := AESCbcDecrypter(key, iv, secretKey)
	if err != nil {
		return false, err
	}
	values := strings.Split(string(decriptedSecretKey), ";")
	expire, err := strconv.ParseFloat(values[4], 64)
	if err != nil {
		return false, err
	}
	timestamp, err := strconv.ParseInt(values[2], 10, 64)
	if err != nil {
		return false, err
	}
	secretKeyCreatedAt := time.Unix(timestamp, 0)
	expireDuration := expire * 60.0
	secretKeyDuration := time.Since(secretKeyCreatedAt).Minutes()
	return secretKeyDuration < expireDuration, nil
}

// CreateNewClientID generate SHA-256 hash string
func CreateNewClientID(email string) string {
	timestamp := time.Now().UnixNano()
	stamp := GenerateRandomStringFixedLenght(StampLength, timestamp)
	s := fmt.Sprintf(clientIDLayout, email, timestamp, stamp)
	return generateSHA256Hash(generateSHA256Hash(s))
}

// GenerateAccessToken generate SHA-256 hash string
// expire in seconds
func GenerateAccessToken(clientID, secreteKeyID string, expire int) (string, error) {
	timestamp := time.Now().UnixNano()
	preTokenStamp := fmt.Sprintf(clientIDLayout, clientID, secreteKeyID, timestamp)
	tokenStamp := generateSHA256Hash(preTokenStamp)
	s := fmt.Sprintf(tokenLayout, clientID, timestamp, tokenStamp, expire)
	iv := config.GetString("general.secure_token_iv")
	key := config.GetString("general.secure_token_key")
	hash, err := AESCbcEncrypter(key, iv, s)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// ValidateAccessToken validate token
// Return the client_id. The bool value indicate whether the token is valid.
func ValidateAccessToken(token string) (string, bool, error) {
	iv := config.GetString("general.secure_token_iv")
	key := config.GetString("general.secure_token_key")
	decriptedToken, err := AESCbcDecrypter(key, iv, token)
	if err != nil {
		return "", false, err
	}
	values := strings.Split(string(decriptedToken), ";")
	expire, err := strconv.ParseFloat(values[3], 64)
	if err != nil {
		return "", false, err
	}
	timestamp, err := strconv.ParseInt(values[1], 10, 64)
	if err != nil {
		return "", false, err
	}
	tokenCreatedAt := time.Unix(timestamp, 0)
	expireDuration := expire * 60.0
	tokenDuration := time.Since(tokenCreatedAt).Minutes()
	if tokenDuration >= expireDuration {
		return "", false, nil
	}
	return values[0], true, nil
}

// ValidateAccessTokenFunc doc ...
func ValidateAccessTokenFunc(token string) (json.RawMessage, bool) {
	tokenData, valid, err := ValidateAccessToken(token)
	if err != nil {
		log.Error(err)
		return nil, false
	}
	return []byte(tokenData), valid
}
