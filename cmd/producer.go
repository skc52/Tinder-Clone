package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"os"

	"github.com/IBM/sarama"
)

type Message struct {
	UserId     int    `json:"user_id"`
	PostId     string `json:"post_id"`
	UserAction string `json:"user_action"`
}

func mainP() {
	brokers := []string{"localhost:9093"}
	producer, err := sarama.NewSyncProducer(brokers, nil)
	if err != nil {
		log.Fatalln("Failed to start Sarama producer:", err)
		os.Exit(1)
	}

	// Dummy Data
	userId := [5]int{100001, 100002, 100003, 100004, 100005}
	postId := [5]string{"POST00001", "POST00002", "POST00003", "POST00004", "POST00005"}
	userAction := [5]string{"love", "like", "hate", "smile", "cry"}

	for {
		// we are going to take random data from the dummy data
		message := Message{
			UserId:     userId[rand.Intn(len(userId))],
			PostId:     postId[rand.Intn(len(postId))],
			UserAction: userAction[rand.Intn(len(userAction))],
		}

		jsonMessage, err := json.Marshal(message)

		if err != nil {
			log.Fatalln("Failed to marshal message:", err)
			os.Exit(1)
		}

		msg := &sarama.ProducerMessage{
			Topic: "post-likes",
			Value: sarama.StringEncoder(jsonMessage),
		}

		_, _, err = producer.SendMessage(msg)
		if err != nil {
			log.Fatalln("Failed to send message:", err)
			os.Exit(1)
		}
		log.Println("Message sent!")
	}
}
