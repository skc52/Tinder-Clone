# Start with a base Go image
FROM golang:latest



# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules and build files
# Add dockerize binary
# RUN wget https://github.com/jwilder/dockerize/releases/download/v0.6.1/dockerize-linux-amd64-v0.6.1.tar.gz \
#     && tar -C /usr/local/bin -xzf dockerize-linux-amd64-v0.6.1.tar.gz \
#     && rm dockerize-linux-amd64-v0.6.1.tar.gz

# COPY wait-for-it.sh /usr/local/bin/wait-for-it.sh
# RUN chmod +x /usr/local/bin/wait-for-it.sh
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
