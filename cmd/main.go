package main

import (
	"log"
	"myserver/api"
	"myserver/kafka"
)

func main() {
	// Initialize Kafka consumers
	kafka.InitKafka()

	portStr := "8081"                        // Port number for the server
	server := api.NewMyServer(":" + portStr) // Create a new server instance with the specified port

	// Run the server and log any error that occurs
	if err := server.Run(); err != nil {
		log.Fatal(err) // Log the error and exit if the server fails to start
	}
}
