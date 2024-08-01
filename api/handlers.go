package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"myserver/model"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
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

	// Apply JWTMiddleware to the /setUpProfile route
	profileRoute := router.PathPrefix("/setUpProfile").Subrouter()
	profileRoute.Use(JWTMiddleware) // Apply JWT middleware here
	profileRoute.HandleFunc("", h.setupProfileHandler).Methods("POST")

	// Route for liking a user profile
	likeRoute := router.PathPrefix("/like/{user_id}").Subrouter()
	likeRoute.Use(JWTMiddleware) // Apply JWT middleware here
	likeRoute.HandleFunc("", h.likeUser).Methods("POST")

	// Route for retrieving all matches
	matchRoute := router.PathPrefix("/matches/{user_id}").Subrouter()
	matchRoute.Use(JWTMiddleware) // Apply JWT middleware here
	matchRoute.HandleFunc("", h.getMatches).Methods("GET")
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

	profile.UserID = user.ID

	// Create or update profile
	if err := model.DB.Save(&profile).Error; err != nil {
		http.Error(w, "Failed to save profile", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(profile)
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

		// A match is found, create a new entry in the Matches table
		match := model.Match{
			User1: uint(likerID),
			User2: uint(likeeID),
		}
		if err := model.DB.Create(&match).Error; err != nil {
			http.Error(w, "Failed to create match", http.StatusInternalServerError)
			return
		}

		message := "You matched with user " + strconv.FormatUint(uint64(likeeID), 10)
		response := map[string]string{"message": message}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	} else {
		// No match found
		message := "You received a new like"
		response := map[string]string{"message": message}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
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

// TODO RETRIEVE PROFILES FOR THE USER TO LIKE
// USE a queue for this..liked profiles will ve remoed from the queue
// unliked profile will be moved to the back of the queue
// also allow for filtering based on age range
