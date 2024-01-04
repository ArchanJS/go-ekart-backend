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
	routes.HandleFunc("/user", createUser).Methods("POST")
	routes.HandleFunc("/user/login", login).Methods("POST")
	routes.HandleFunc("/user", fetchUserDataByToken).Methods("GET")

	log.Fatal(http.ListenAndServe(":8000", routes))

}
