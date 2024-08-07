#!/bin/bash

# Wait for Kafka to be fully up
echo "Waiting for Kafka to be available..."
while ! docker-compose exec kafka kafka-topics.sh --list --bootstrap-server localhost:9092 >/dev/null 2>&1; do
  sleep 1
done

# Create topics
echo "Creating topics..."
docker-compose exec kafka kafka-topics.sh --create --topic user_likes --partitions 1 --replication-factor 1 --bootstrap-server localhost:9092
docker-compose exec kafka kafka-topics.sh --create --topic user_matches --partitions 1 --replication-factor 1 --bootstrap-server localhost:9092

echo "Topics created."
