package main

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func db() *mongo.Client {
	clientOptions := options.Client().ApplyURI("mongodb+srv://archan:987kL3Taipr2rXoW@cluster0.pqzn9.mongodb.net/go-ekart?retryWrites=true&w=majority")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}
	er := client.Ping(context.TODO(), nil)

	if er != nil {
		panic(er)
	}

	fmt.Println("DB Conneted")
	return client
}
