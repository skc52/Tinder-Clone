#!/bin/bash

# Variables
KAFKA_HOME="/opt/kafka"  # Adjust this path to where Kafka is installed
BROKER_LIST="localhost:9092"  # Adjust this if your Kafka broker is at a different address

# Topics to create
TOPIC1="user_likes"
TOPIC2="user_matches"
PARTITIONS=1
REPLICATION_FACTOR=1

# Create the first Kafka topic
$KAFKA_HOME/bin/kafka-topics.sh --create \
    --bootstrap-server $BROKER_LIST \
    --replication-factor $REPLICATION_FACTOR \
    --partitions $PARTITIONS \
    --topic $TOPIC1

# Create the second Kafka topic
$KAFKA_HOME/bin/kafka-topics.sh --create \
    --bootstrap-server $BROKER_LIST \
    --replication-factor $REPLICATION_FACTOR \
    --partitions $PARTITIONS \
    --topic $TOPIC2

# Verify the topics creation
$KAFKA_HOME/bin/kafka-topics.sh --list --bootstrap-server $BROKER_LIST
