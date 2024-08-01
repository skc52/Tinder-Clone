# Start with a base Go image
FROM golang:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules and build files
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go application
RUN make build

# Expose the port your application listens on
EXPOSE 8081

# Command to run the application
CMD ["./bin/tinder_clone"]
