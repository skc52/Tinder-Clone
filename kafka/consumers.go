package kafka

import (
	"context"
	"log"
	"myserver/model"
	"strconv"
	"time"

	"github.com/IBM/sarama"
)

var kafkaConn string = "kafka:9092"

type likeEventsHandler struct{}
type matchEventsHandler struct{}

func (likeEventsHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (likeEventsHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
func (h likeEventsHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		likerID := string(msg.Key)
		likeeID := string(msg.Value)
		if err := notifyUserOfLike(likerID, likeeID); err != nil {
			log.Printf("Failed to notify user of like: %v", err)
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}

func (matchEventsHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (matchEventsHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
func (h matchEventsHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		user1ID := string(msg.Key)
		user2ID := string(msg.Value)
		if err := notifyUsersOfMatch(user1ID, user2ID); err != nil {
			log.Printf("Failed to notify users of match: %v", err)
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}

func consumeLikeEvents() {
	brokers := []string{kafkaConn} // Updated to use Docker network address
	groupID := "like-events-group"

	config := sarama.NewConfig()
	config.Version = sarama.V2_0_0_0
	config.Consumer.Offsets.AutoCommit.Enable = true
	config.Consumer.Offsets.AutoCommit.Interval = 1 * time.Second

	consumerGroup, err := sarama.NewConsumerGroup(brokers, groupID, config)
	if err != nil {
		log.Fatalf("Error creating consumer group client: %v", err)
	}

	ctx := context.Background()

	for {
		if err := consumerGroup.Consume(ctx, []string{"user_likes"}, likeEventsHandler{}); err != nil {
			log.Fatalf("Error from consumer: %v", err)
		}
	}
}

func consumeMatchEvents() {
	brokers := []string{kafkaConn} // Updated to use Docker network address
	groupID := "match-events-group"

	config := sarama.NewConfig()
	config.Version = sarama.V2_0_0_0
	config.Consumer.Offsets.AutoCommit.Enable = true
	config.Consumer.Offsets.AutoCommit.Interval = 1 * time.Second

	consumerGroup, err := sarama.NewConsumerGroup(brokers, groupID, config)
	if err != nil {
		log.Fatalf("Error creating consumer group client: %v", err)
	}

	ctx := context.Background()

	for {
		if err := consumerGroup.Consume(ctx, []string{"user_matches"}, matchEventsHandler{}); err != nil {
			log.Fatalf("Error from consumer: %v", err)
		}
	}
}

func notifyUserOfLike(likerID, likeeID string) error {
	likeeIDUint, err := strconv.ParseUint(likeeID, 10, 32)
	if err != nil {
		return err
	}

	notification := model.Notification{
		UserID:           uint(likeeIDUint),
		Message:          "You have received a new like!",
		NotificationTime: time.Now(),
	}

	if err := model.DB.Create(&notification).Error; err != nil {
		return err
	}
	return nil
}

func notifyUsersOfMatch(user1ID, user2ID string) error {
	user1IDUint, err := strconv.ParseUint(user1ID, 10, 32)
	if err != nil {
		return err
	}

	user2IDUint, err := strconv.ParseUint(user2ID, 10, 32)
	if err != nil {
		return err
	}

	notification1 := model.Notification{
		UserID:           uint(user1IDUint),
		Message:          "You have a new match!",
		NotificationTime: time.Now(),
	}

	notification2 := model.Notification{
		UserID:           uint(user2IDUint),
		Message:          "You have a new match!",
		NotificationTime: time.Now(),
	}

	if err := model.DB.Create(&notification1).Error; err != nil {
		return err
	}

	if err := model.DB.Create(&notification2).Error; err != nil {
		return err
	}

	return nil
}

type dummyEventsHandler struct{}

func (dummyEventsHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (dummyEventsHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (h dummyEventsHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		key := string(msg.Key)
		value := string(msg.Value)
		log.Printf("Processing dummy event: key=%s, value=%s", key, value) // Debug log
		if err := notifyUsersOfDummy(); err != nil {
			log.Printf("Failed to notify users of dummy: %v", err)
		}
		// Here you can add any processing logic you want for the dummy event
		log.Printf("Dummy event processed: key=%s, value=%s", key, value)
		sess.MarkMessage(msg, "")
	}
	return nil
}

func notifyUsersOfDummy() error {

	notification1 := model.Notification{
		UserID:           1,
		Message:          "You have a new notification!",
		NotificationTime: time.Now(),
	}

	if err := model.DB.Create(&notification1).Error; err != nil {
		return err
	}

	return nil
}

func consumeDummyEvents() {
	brokers := []string{kafkaConn} // Updated to use Docker network address
	groupID := "dummy-events-group"

	config := sarama.NewConfig()
	config.Version = sarama.V2_0_0_0
	config.Consumer.Offsets.AutoCommit.Enable = true
	config.Consumer.Offsets.AutoCommit.Interval = 1 * time.Second

	consumerGroup, err := sarama.NewConsumerGroup(brokers, groupID, config)
	if err != nil {
		log.Fatalf("Error creating consumer group client: %v", err)
	}

	ctx := context.Background()

	for {
		if err := consumerGroup.Consume(ctx, []string{"dummy_topic"}, dummyEventsHandler{}); err != nil {
			log.Fatalf("Error from consumer: %v", err)
		}
	}
}
