# Use the official Golang 1.23.1 image as the base image
FROM golang:1.23.1

# Set the working directory inside the container
WORKDIR /app

# Verify Go installation
RUN go version

# Copy the entire project into the container
COPY . .

# Download dependencies
RUN go mod tidy

# Build the application
RUN go build -o app

# Set the default command to run the application
CMD ["./app"]
