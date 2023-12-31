package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()

	routes := router.PathPrefix("/api").Subrouter()

	routes.HandleFunc("/product", createProduct).Methods("POST")
	routes.HandleFunc("/product", getAllProducts).Methods("GET")
	routes.HandleFunc("/product/{id}", getSingleProduct).Methods("GET")
	routes.HandleFunc("/product/{id}", buyProduct).Methods("PUT")

	log.Fatal(http.ListenAndServe(":8000", routes))

}
