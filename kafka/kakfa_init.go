package kafka

import (
	"sync"
	"time"
)

var once sync.Once

func InitKafka() {
	once.Do(func() {
		// Wait for 10 seconds before starting consumers
		time.Sleep(10 * time.Second)

		go consumeLikeEvents()
		go consumeMatchEvents()
		go consumeDummyEvents() // Add this line to start the dummy events consumer
	})
}
