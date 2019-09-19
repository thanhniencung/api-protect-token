package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("abcdefghijklmnopq")

type Error struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type Claims struct {
	Email       string `json:"email"`
	jwt.StandardClaims
}

type LoginData struct {
	Email string
	Pass string
}

type Response struct {
	Token  string `json:"token"`
	Status int    `json:"status"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	var loginData LoginData
	err := json.NewDecoder(r.Body).Decode(&loginData)
	if err != nil {
		ResponseErr(w, http.StatusBadRequest)
		return
	}

	var tokenString string
	tokenString, err = GenToken(loginData.Email)

	if err != nil {
		ResponseErr(w, http.StatusInternalServerError)
		return
	}

	ResponseOk(w, Response{
		Token:  tokenString,
		Status: http.StatusOK,
	})
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	tokenHeader := r.Header.Get("Authorization")

	if tokenHeader == "" {
		ResponseErr(w, http.StatusForbidden)
		return
	}

	splitted := strings.Split(tokenHeader, " ") // Bearer jwt_token
	if len(splitted) != 2 {
		ResponseErr(w, http.StatusForbidden)
		return
	}

	tokenPart := splitted[1]

	key := []byte("d20f3a68ccad575516961efae2f73148")
	tokenDecrypt, _ := decrypt(key, tokenPart)

	tk := &Claims{}

	token, err := jwt.ParseWithClaims(tokenDecrypt, tk, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		fmt.Println(err)
		ResponseErr(w, http.StatusInternalServerError)
		return
	}

	if token.Valid {
		ResponseOk(w, token.Claims)
	}
}

func GenToken(email string) (string, error) {
	expirationTime := time.Now().Add(120 * time.Second)
	claims := &Claims{
		Email:       email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	result, _ := token.SignedString(jwtKey)

	key := []byte("d20f3a68ccad575516961efae2f73148")
	encryptToken, _ := encrypt(key, result)

	return encryptToken, nil
}

func ResponseErr(w http.ResponseWriter, statusCode int) {
	jData, err := json.Marshal(Error{
		Status:  statusCode,
		Message: http.StatusText(statusCode),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jData)
}

func ResponseOk(w http.ResponseWriter, data interface{}) {
	if data == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jData, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jData)
}

func addBase64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)
	}

	return value
}

func removeBase64Padding(value string) string {
	return strings.Replace(value, "=", "", -1)
}

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

func encrypt(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	msg := Pad([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
	finalMsg := removeBase64Padding(base64.URLEncoding.EncodeToString(ciphertext))
	return finalMsg, nil
}

func decrypt(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedMsg, err := base64.URLEncoding.DecodeString(addBase64Padding(text))
	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("blocksize must be multipe of decoded message length")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unpadMsg, err := Unpad(msg)
	if err != nil {
		return "", err
	}

	return string(unpadMsg), nil
}
