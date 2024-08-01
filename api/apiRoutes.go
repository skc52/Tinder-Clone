package api

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

type MyServer struct {
	addr string
}

func (m *MyServer) Run() error {
	router := mux.NewRouter()

	// Add a prefix to maintain versioning in API
	subRouter := router.PathPrefix("/api/v1").Subrouter()

	// Create handlers and register them to the subrouter
	h := Handler{}
	h.RegisterRoutes(subRouter)

	fmt.Println("Listening on: ", m.addr)

	// Start the server and handle errors
	err := http.ListenAndServe(m.addr, subRouter)
	if err != nil {
		fmt.Println("Server error:", err)
	}
	return err
}

func NewMyServer(addr string) *MyServer {
	return &MyServer{addr: addr}
}
