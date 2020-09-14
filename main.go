package main

import (
	"first-app/utils"
	"log"
	"net/http"
)

func main() {
	log.Printf("Listening on localhost:8080")
	http.HandleFunc("/arpSpoof", utils.SpooferHandler)
	http.HandleFunc("/devices", utils.DevicesHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
