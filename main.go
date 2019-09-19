package main

import (
	"net/http"
)



func main() {
	http.HandleFunc("/login", Login)
	http.HandleFunc("/user", GetUser)
	http.ListenAndServe(":8000", nil)
}