package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"myserver/kafka"
	"myserver/model"
	"net/http"
	"strconv"
	"sync"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var jwtSecret = []byte("your_secret_key") // Use a secure key

// create a middleware that checks for authentication
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt_token")
		if err != nil {
			http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrNotSupported
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		username := claims["username"].(string)
		var user model.User
		if err := model.DB.Where("username = ?", username).First(&user).Error; err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		context.Set(r, "user", user)
		next.ServeHTTP(w, r)
	})
}

type Handler struct{}

// RegisterRoutes initializes the routes for the API
func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/home", h.showHomePage).Methods("GET")
	router.HandleFunc("/register", h.RegisterUser).Methods("POST")
	router.HandleFunc("/login", h.LoginUser).Methods("POST")

	router.HandleFunc("/users", h.fetchAllUsers).Methods("GET")

	// Apply JWTMiddleware to the /setUpProfile route
	profileRoute := router.PathPrefix("/setUpProfile").Subrouter()
	profileRoute.Use(JWTMiddleware) // Apply JWT middleware here
	profileRoute.HandleFunc("", h.setupProfileHandler).Methods("POST")

	// REMOVE THI LATER
	// Apply JWTMiddleware to the /setUpProfile route
	dummyKafkaRoute := router.PathPrefix("/dummy").Subrouter()
	dummyKafkaRoute.Use(JWTMiddleware) // Apply JWT middleware here
	dummyKafkaRoute.HandleFunc("", h.dummyHandler).Methods("POST")

	// Route for liking a user profile
	likeRoute := router.PathPrefix("/like/{user_id}").Subrouter()
	likeRoute.Use(JWTMiddleware) // Apply JWT middleware here
	likeRoute.HandleFunc("", h.likeUser).Methods("POST")

	// Route for retrieving all matches
	matchRoute := router.PathPrefix("/matches/{user_id}").Subrouter()
	matchRoute.Use(JWTMiddleware) // Apply JWT middleware here
	matchRoute.HandleFunc("", h.getMatches).Methods("GET")

	// Route to fetch user and profile by ID
	userProfileRoute := router.PathPrefix("/user/{user_id}").Subrouter()
	userProfileRoute.Use(JWTMiddleware)
	userProfileRoute.HandleFunc("", h.fetchUserProfileByID).Methods("GET")

	//get next user
	nextProfileRoute := router.PathPrefix("/profile/next").Subrouter()
	nextProfileRoute.Use(JWTMiddleware)
	nextProfileRoute.HandleFunc("", h.getNextUserToShow).Methods("GET")

	//get all notifications TODO MODIFY TO ONLY SHOW OWN NOTIFICATIONS
	notificationRoute := router.PathPrefix("/notifications/all").Subrouter()
	notificationRoute.Use(JWTMiddleware)
	notificationRoute.HandleFunc("", h.getAllNotifications).Methods("GET")

}

func (h *Handler) dummyHandler(w http.ResponseWriter, r *http.Request) {

	// Call dummy producer
	kafka.ProduceDummyEvent()

	// Prepare the response
	response := map[string]string{"message": "Dummy event produced successfully"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}

}

// fetchAllUsers handles the request to fetch all users
func (h *Handler) fetchAllUsers(w http.ResponseWriter, r *http.Request) {

	// Query for all users
	var users []model.User
	if err := model.DB.Find(&users).Error; err != nil {
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	// Prepare the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// showHomePage handles the request for the home page
func (h *Handler) showHomePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Welcome to the Home Page!")
}

// RegisterUser handles the user registration
func (h *Handler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user model.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	user.PasswordHash = string(hash)

	// Use GORM to create the user
	result := model.DB.Create(&user)
	if result.Error != nil {
		http.Error(w, "Error creating user: "+result.Error.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "User registered successfully"}`))
}

// LoginUser handles user login and token generation
func (h *Handler) LoginUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var inputUser model.User
	if err := json.NewDecoder(r.Body).Decode(&inputUser); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Find the user by username
	var user model.User
	result := model.DB.Where("username = ?", inputUser.Username).First(&user)
	if result.Error != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Compare the hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(inputUser.PasswordHash)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create and sign JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Store JWT token in cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
	})

	w.WriteHeader(http.StatusOK)
	// w.Write([]byte(`{"message": "User loggedin successfully"}`))

	w.Write([]byte(`{"token": "` + tokenString + `"}`))

}

func (h *Handler) setupProfileHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := context.Get(r, "user").(model.User)
	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	var profile model.Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	lat, lon, err := GetCurrentLocation()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get current location: %v", err), http.StatusInternalServerError)
		return
	}

	profile.Location = model.Location{
		Latitude:  lat,
		Longitude: lon,
	}

	profile.UserID = user.ID

	// Create or update profile
	if err := model.DB.Save(&profile).Error; err != nil {
		http.Error(w, "Failed to save profile", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(profile)
}

func (h *Handler) setUpFilter(w http.ResponseWriter, r *http.Request) {
	user, ok := context.Get(r, "user").(model.User)
	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	var filter model.Filter

	// Decode the request body into the Filter struct
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate filter fields
	if filter.Gender == "" {
		http.Error(w, "Gender is required", http.StatusBadRequest)
		return
	}
	if filter.LowerAge < 0 || filter.UpperAge < filter.LowerAge {
		http.Error(w, "Invalid age range", http.StatusBadRequest)
		return
	}
	if filter.Radius <= 0 {
		http.Error(w, "Radius must be greater than zero", http.StatusBadRequest)
		return
	}

	// Check if a filter already exists for the user
	var existingFilter model.Filter
	if err := model.DB.Where("user_id = ?", user.ID).First(&existingFilter).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "Failed to check existing filter", http.StatusInternalServerError)
		return
	}

	// Update or create the filter
	filter.UserID = user.ID
	if existingFilter.ID != 0 {
		// Update existing filter
		if err := model.DB.Model(&existingFilter).Updates(filter).Error; err != nil {
			http.Error(w, "Failed to update filter", http.StatusInternalServerError)
			return
		}
	} else {
		// Create new filter
		if err := model.DB.Create(&filter).Error; err != nil {
			http.Error(w, "Failed to create filter", http.StatusInternalServerError)
			return
		}
	}

	// Respond with success
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Filter set up successfully"))
}

// LIKE user

// likeUser handles the like action from the current user to another user
func (h *Handler) likeUser(w http.ResponseWriter, r *http.Request) {
	// Extract the user ID to be liked from the URL
	vars := mux.Vars(r)
	likeeIDStr := vars["user_id"]
	likeeID, err := strconv.ParseUint(likeeIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Get the current user's ID from the JWT token
	user, ok := context.Get(r, "user").(model.User)
	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}
	likerID := user.ID

	// Create a new entry in the likes table
	like := model.Like{
		LikerID: uint(likerID),
		LikeeID: uint(likeeID),
	}
	if err := model.DB.Create(&like).Error; err != nil {
		http.Error(w, "Failed to create like", http.StatusInternalServerError)
		return
	}

	// Check if a match has occurred
	var reverseLike model.Like
	if err := model.DB.Where("liker_id = ? AND likee_id = ?", likeeID, likerID).First(&reverseLike).Error; err == nil {
		// A match is found

		// Create a new entry in the Matches table
		match := model.Match{
			User1: uint(likerID),
			User2: uint(likeeID),
		}
		if err := model.DB.Create(&match).Error; err != nil {
			http.Error(w, "Failed to create match", http.StatusInternalServerError)
			return
		}

		// Produce a match event to Kafka
		kafka.ProduceMatchEvent(uint(likerID), uint(likeeID))

		message := "You have a new match."
		response := map[string]string{"message": message}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	} else {
		// No match found

		// Produce a like event to Kafka
		kafka.ProduceLikeEvent(uint(likerID), uint(likeeID))

		message := "You sent a new like."
		response := map[string]string{"message": message}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// DISLIKE USERS
func (h *Handler) dislikeUser(w http.ResponseWriter, r *http.Request) {
	// Extract the user ID to be liked from the URL
	vars := mux.Vars(r)
	dislikeeIDStr := vars["user_id"]
	dislikeeID, err := strconv.ParseUint(dislikeeIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Get the current user's ID from the JWT token
	user, ok := context.Get(r, "user").(model.User)
	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}
	dislikerID := user.ID

	// Create a new entry in the likes table
	dislike := model.DisLike{
		DisLikerID: uint(dislikerID),
		DisLikeeID: uint(dislikeeID),
	}
	if err := model.DB.Create(&dislike).Error; err != nil {
		http.Error(w, "Failed to create dislike", http.StatusInternalServerError)
		return
	}

	message := "You sent a new dislike"
	response := map[string]string{"message": message}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

}

//fetch all matches

func (h *Handler) getMatches(w http.ResponseWriter, r *http.Request) {
	// get the current user's ID from the JWT token
	user, ok := context.Get(r, "user").(model.User)

	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	userId := user.ID

	// Query for matches where the current user is either user1 or user2
	var matches []model.Match
	if err := model.DB.Where("user1 = ? OR user2 = ?", userId, userId).Find(&matches).Error; err != nil {
		http.Error(w, "Failed to retrieve matches", http.StatusInternalServerError)
		return
	}

	//Prepare the response - list of user ids of all matches
	response := []uint{}
	for _, match := range matches {
		if match.User1 != userId {
			response = append(response, match.User1)
		}
		if match.User2 != userId {
			response = append(response, match.User2)
		}
	}

	// send the response
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// Get User info based on ID
func (h *Handler) fetchUserProfileByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["user_id"]
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Fetch user info
	var user model.User

	if err := model.DB.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Fetch profile info
	var profile model.Profile
	if err := model.DB.Where("user_id = ?", userID).First(&profile).Error; err != nil {
		http.Error(w, "Profile not Found", http.StatusNotFound)
		return
	}

	// Prepare the response
	response := struct {
		User    model.User    `json:"user"`
		Profile model.Profile `json:"profile"`
	}{
		User:    user,
		Profile: profile,
	}

	// Send the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

var queue []model.User
var queueMutex sync.Mutex

// loadQueue loads users into the queue who haven't been liked or disliked yet
func loadQueue(db *gorm.DB, userID uint) {
	// Fetch filter settings for the current user
	var filter model.Filter
	err := db.First(&filter, "user_id = ?", userID).Error
	if err != nil {
		fmt.Printf("Error loading filter: %v\n", err)
		return
	}

	// Fetch users based on the filter
	var users []model.User
	err = db.Table("users").
		Select("users.*").
		Where("users.id != ?", userID).
		Where("users.id NOT IN (SELECT likee_id FROM likes WHERE liker_id = ?)", userID).
		Where("users.id NOT IN (SELECT dis_likee_id FROM dis_likes WHERE dis_liker_id = ?)", userID).
		Where("gender = ?", filter.Gender).
		Where("age BETWEEN ? AND ?", filter.LowerAge, filter.UpperAge).
		Where("ST_Distance_Sphere(location, (SELECT location FROM users WHERE id = ?)) <= ?", userID, filter.Radius*1000).
		Find(&users).Error
	if err != nil {
		fmt.Printf("Error loading users: %v\n", err)
		return
	}

	// Update the global queue
	queueMutex.Lock()
	defer queueMutex.Unlock()
	queue = users
}

// getNextUserToShow retrieves the next user from the queue and handles the response
func (h *Handler) getNextUserToShow(w http.ResponseWriter, r *http.Request) {
	// Get the current user's ID from the request context or query parameters
	user, ok := context.Get(r, "user").(model.User)
	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}
	userID := user.ID

	queueMutex.Lock()
	defer queueMutex.Unlock()

	if len(queue) == 0 {
		// Load more users if the queue is empty
		loadQueue(model.DB, userID)
	}

	if len(queue) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "No users to show"}); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
		return
	}

	// Show the next user in the queue
	userToShow := queue[0]
	queue = queue[1:]

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userToShow); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

//get all notifications

func (h *Handler) getAllNotifications(w http.ResponseWriter, r *http.Request) {

	// Fetch all notifications from the database
	var notifications []model.Notification
	if err := model.DB.Find(&notifications).Error; err != nil {
		http.Error(w, "Error retrieving notifications", http.StatusInternalServerError)
		return
	}

	// Respond with notifications
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(notifications); err != nil {
		http.Error(w, "Error encoding notifications", http.StatusInternalServerError)
	}
}
