package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type sizes struct {
	Size     string `json:"size"`
	Quantity int    `json:"quantity"`
}

type product struct {
	Title string  `json:"title"`
	Photo string  `json:"photo"`
	Price int     `json:"price"`
	Stock []sizes `json:"stock"`
}

type user struct {
	Name     string `json:"name"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

var productCol = db().Database("goekart").Collection("product")
var userCol = db().Database("goekart").Collection("user")

var HashKey = []byte("randomsecret")

func createProduct(res http.ResponseWriter, req *http.Request) {
	// fmt.Println("Hello")
	res.Header().Set("Content-Type", "application/json")
	var products []product
	bodyDecodeErr := json.NewDecoder(req.Body).Decode(&products)
	if bodyDecodeErr != nil {
		http.Error(res, bodyDecodeErr.Error(), http.StatusInternalServerError)
		return
	}

	var productIFs []interface{}

	for _, prod := range products {
		productIFs = append(productIFs, prod)
	}

	result, creationErr := productCol.InsertMany(context.TODO(), productIFs)

	if creationErr != nil {
		http.Error(res, creationErr.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(res).Encode(result)
}

func getAllProducts(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	data, fetchErr := productCol.Find(context.TODO(), bson.D{})

	if fetchErr != nil {
		http.Error(res, fetchErr.Error(), http.StatusInternalServerError)
		return
	}
	var products []primitive.M

	for data.Next(context.TODO()) {
		var prod primitive.M
		decodeErr := data.Decode(&prod)

		if decodeErr != nil {
			http.Error(res, decodeErr.Error(), http.StatusInternalServerError)
			return
		}
		products = append(products, prod)

	}

	json.NewEncoder(res).Encode(products)
}

func getSingleProduct(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	param := mux.Vars(req)["id"]
	_id, paramErr := primitive.ObjectIDFromHex(param)

	if paramErr != nil {
		http.Error(res, paramErr.Error(), http.StatusInternalServerError)
		return
	}

	filter := bson.D{{"_id", _id}}

	var prod product

	fetchErr := productCol.FindOne(context.TODO(), filter).Decode(&prod)

	if fetchErr != nil {
		http.Error(res, paramErr.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(res).Encode(prod)
}

func buyProduct(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	param := mux.Vars(req)["id"]
	var body sizes
	bodyDecodeErr := json.NewDecoder(req.Body).Decode(&body)

	if bodyDecodeErr != nil {
		http.Error(res, bodyDecodeErr.Error(), http.StatusInternalServerError)
		return
	}

	_id, idErr := primitive.ObjectIDFromHex(param)

	if idErr != nil {
		http.Error(res, idErr.Error(), http.StatusInternalServerError)
		return
	}

	var prod product

	fetchErr := productCol.FindOne(context.TODO(), bson.D{{"_id", _id}}).Decode(&prod)

	if fetchErr != nil {
		http.Error(res, fetchErr.Error(), http.StatusNotFound)
		return
	}

	for idx, item := range prod.Stock {
		if item.Size == body.Size {
			if item.Quantity < body.Quantity {
				http.Error(res, "Not enough product is available", http.StatusBadRequest)
				return
			}
			prod.Stock[idx].Quantity = item.Quantity - body.Quantity
		}
	}

	filter := bson.D{{"_id", _id}}
	afterOptions := options.After

	after := options.FindOneAndUpdateOptions{
		ReturnDocument: &afterOptions,
	}

	updatedData := bson.D{{"$set", bson.D{{"stock", prod.Stock}}}}
	// fmt.Println(prod.Stock)
	var updatedProd product
	productCol.FindOneAndUpdate(context.TODO(), filter, updatedData, &after).Decode(&updatedProd)

	json.NewEncoder(res).Encode(updatedProd)

}

func createUser(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	var body user
	decodeErr := json.NewDecoder(req.Body).Decode(&body)
	if decodeErr != nil {
		fmt.Println(decodeErr)
		http.Error(res, decodeErr.Error(), http.StatusInternalServerError)
		return
	}
	hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if hashErr != nil {
		fmt.Println(hashErr)
		http.Error(res, hashErr.Error(), http.StatusInternalServerError)
		return
	}
	body.Password = string(hashedPassword)
	indexModel := mongo.IndexModel{
		Keys:    bson.M{"phone": 1},
		Options: options.Index().SetUnique(true),
	}
	userCol.Indexes().CreateOne(context.TODO(), indexModel)
	userData, userErr := userCol.InsertOne(context.TODO(), body)

	if userErr != nil {
		fmt.Println(userErr)
		http.Error(res, userErr.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(res).Encode(userData)
}

func login(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	type reqBody struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	var body reqBody
	decodeErr := json.NewDecoder(req.Body).Decode(&body)
	if decodeErr != nil {
		fmt.Println(decodeErr)
		http.Error(res, decodeErr.Error(), http.StatusInternalServerError)
		return
	}
	filter := bson.D{{"phone", body.Phone}}
	var decodedData user
	fetchErr := userCol.FindOne(context.TODO(), filter).Decode(&decodedData)
	if fetchErr != nil {
		fmt.Println(fetchErr)
		http.Error(res, fetchErr.Error(), http.StatusInternalServerError)
		return
	}
	decryptErr := bcrypt.CompareHashAndPassword([]byte(decodedData.Password), []byte(body.Password))
	if decryptErr != nil {
		fmt.Println(decryptErr)
		http.Error(res, "Invalid credentials", http.StatusBadRequest)
		return
	}
	claims := jwt.MapClaims{
		"id":  body.Password,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 30000).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, signErr := token.SignedString(HashKey)
	if signErr != nil {
		fmt.Println(signErr)
		http.Error(res, signErr.Error(), http.StatusInternalServerError)
		return
	}
	type response struct {
		Name  string `json:"name"`
		Phone string `json:"phone"`
		Token string `json:"token"`
	}
	var userResponse response
	userResponse.Name = decodedData.Name
	userResponse.Phone = decodedData.Phone
	userResponse.Token = signedToken
	json.NewEncoder(res).Encode(userResponse)
}
