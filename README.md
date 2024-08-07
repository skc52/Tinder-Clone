Must have docker installed

- git clone <repository_url>
- docker-compose build
- docker-compose up

<!-- DATABASE WILL BE RUNNING in localhost:5432 -->
<!-- App will be accessible in localhost:8081 -->

# Access Kafka container

docker exec -it myserver-kafka-1 bash

# Inside the container, run:

kafka-topics.sh --create --bootstrap-server localhost:9092 --replication-factor 1 --partitions 1 --topic user_likes
kafka-topics.sh --create --bootstrap-server localhost:9092 --replication-factor 1 --partitions 1 --topic user_matches
kafka-topics.sh --list --bootstrap-server localhost:9092

# Exit the container

exit
