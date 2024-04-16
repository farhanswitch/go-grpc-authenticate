package main

import (
	"context"
	"log"
	"time"

	pb "github.com/farhanswitch/grpc-auth/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	ADDRESS = ":50053"
)

func main() {
	conn, err := grpc.Dial(ADDRESS, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Cannot connect to GRPC Server.\nError: %s\n", err.Error())
	}
	defer conn.Close()
	c := pb.NewAuthServiceClient(conn)
	md := metadata.Pairs("authorization", "Bearer abc")

	ctx := metadata.NewOutgoingContext(context.Background(), md)
	start := time.Now()
	res, err := c.Login(ctx, &pb.LoginRequest{
		Username: "Farhan",
		Password: "asdf123",
	})
	if err != nil {
		log.Printf("Error when Login.\nError: %s\n", err.Error())
		return
	}
	log.Printf("Success Login.Access Token = %s\n Expiration Date: %v\n", res.GetToken(), time.Unix(0, res.GetExpireAt()))

	res2, err := c.Announcement(ctx, &pb.AnnouncementRequest{})
	if err != nil {
		log.Printf("Error when get Announcement.\nError: %s\n", err.Error())
		return
	}
	log.Printf("Success get announcement: %s\n", res2.GetMessage())
	log.Println(time.Since(start))
}
