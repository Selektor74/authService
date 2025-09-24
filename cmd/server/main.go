package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	auth "github.com/Selektor74/authService/gen/go/auth"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

type Server struct {
	auth.UnimplementedAuthServiceServer
	users      map[string]string //username-password
	userIds    map[string]string //username-userId
	nextUserId string
	jwtSecret  []byte
}

var jwtKey = []byte("my_key")

func main() {
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen:%v", err)
	}

	server := grpc.NewServer()

	authServer := &Server{
		users:      make(map[string]string),
		userIds:    make(map[string]string),
		nextUserId: 1,
		jwtSecret:  jwtKey,
	}

	auth.RegisterAuthServiceServer(server, authServer)

	log.Println("gRPC server listeningat", listener.Addr())

	if err := server.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func (server *Server) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	if _, ok := server.users[req.Username]; ok {
		return nil, fmt.Errorf("user with this email already exist")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	userId := server.nextUserId
	server.users[req.Username] = string(hashedPassword)
	server.userIds[req.Username] = userId
	server.nextUserId = "new UUID" //TO DO

	log.Printf("User registered: %s, Id:%d\n", req.Username, userId)

	return &auth.RegisterResponse{UserUuid: userId}, nil
}

func (server *Server) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	hashedPassword, ok := server.users[req.Username]

	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &jwt.RegisteredClaims{
		Subject:   fmt.Sprintf("%d", server.userIds[req.Username]),
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString(server.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create token:%w", err)
	}

	log.Printf("User logged in:%s\n", req.Username)

	return &auth.LoginResponse{Token: tokenString}, nil
}

func (server *Server) Validate(ctx context.Context, req *auth.ValidateRequest) (*auth.ValidateResponse, error) {
	claims := &jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(req.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return server.jwtSecret, nil

	})

	if err != nil {
		log.Printf("Token validation failed:%v", err)
		return &auth.ValidateResponse{IsValid: false}, nil
	}

	if !token.Valid {
		log.Printf("Token is invalid")
		return &auth.ValidateResponse{IsValid: false}, nil
	}

	var userUUID string
	fmt.Scanf(claims.Subject, "%d", &userUUID)

	log.Printf("Token validated for user ID:%d\n", userUUID)

	return &auth.ValidateResponse{IsValid: true, UserUuid: userUUID}, nil
}
