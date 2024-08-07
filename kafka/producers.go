package kafka

import (
	"log"
	"strconv"

	"github.com/IBM/sarama"
)

func ProduceLikeEvent(likerID, likeeID uint) {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true

	producer, err := sarama.NewSyncProducer([]string{"kafka:9092"}, config)
	if err != nil {
		log.Fatalf("Failed to create producer: %v", err)
	}
	defer producer.Close()

	topic := "user_likes"
	message := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(strconv.Itoa(int(likerID))),
		Value: sarama.StringEncoder(strconv.Itoa(int(likeeID))),
	}

	partition, offset, err := producer.SendMessage(message)
	if err != nil {
		log.Fatalf("Failed to produce message: %v", err)
	} else {
		log.Printf("Message is stored in topic(%s)/partition(%d)/offset(%d)\n", topic, partition, offset)
	}
}

func ProduceMatchEvent(user1ID, user2ID uint) {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true

	producer, err := sarama.NewSyncProducer([]string{"kafka:9092"}, config)
	if err != nil {
		log.Fatalf("Failed to create producer: %v", err)
	}
	defer producer.Close()

	topic := "user_matches"
	message := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(strconv.Itoa(int(user1ID))),
		Value: sarama.StringEncoder(strconv.Itoa(int(user2ID))),
	}

	partition, offset, err := producer.SendMessage(message)
	if err != nil {
		log.Fatalf("Failed to produce message: %v", err)
	} else {
		log.Printf("Message is stored in topic(%s)/partition(%d)/offset(%d)\n", topic, partition, offset)
	}
}

func ProduceDummyEvent() {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true

	producer, err := sarama.NewSyncProducer([]string{"kafka:9092"}, config)
	if err != nil {
		log.Fatalf("Failed to create dummy producer: %v", err)
	}
	defer producer.Close()

	topic := "dummy_topic"
	message := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder("Dummy"),
		Value: sarama.StringEncoder("Notification"),
	}

	partition, offset, err := producer.SendMessage(message)
	if err != nil {
		log.Fatalf("Failed to produce dummy message: %v", err)
	} else {
		log.Printf("Message is stored in topic(%s)/partition(%d)/offset(%d)\n", topic, partition, offset)
	}
}
