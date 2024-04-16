package main

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	pb "github.com/farhanswitch/grpc-auth/proto"
	utJwt "github.com/farhanswitch/grpc-auth/utilities/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	PORT = ":50053"
)

var uj = utJwt.NewUtilityJWT()
var listUser []utJwt.UserData = []utJwt.UserData{
	{
		Name:     "Farhan",
		Password: "asdf123",
		Group:    "Admin",
	},
	{
		Name:     "Stevia",
		Password: "abd123",
		Group:    "Officer",
	},
}

func valid(authorization []string) bool {
	if len(authorization) == 0 {
		return false
	}
	token := strings.TrimPrefix(authorization[0], "Bearer ")
	return token == "abc"
}
func EnsureValidToken(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	log.Println(info.FullMethod)
	if info.FullMethod == "/proto.AuthService/Login" {
		return handler(ctx, req)
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "Missing metadata")
	}
	if !valid(md["authorization"]) {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid token")
	}

	return handler(ctx, req)

}

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
}

func (as AuthServer) Announcement(ctx context.Context, req *pb.AnnouncementRequest) (*pb.AnnouncementResponse, error) {
	return &pb.AnnouncementResponse{
		Message: "System running",
	}, nil
}
func (as AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var isValid bool = false
	var user utJwt.UserData
	for _, data := range listUser {
		if data.Name == req.GetUsername() {
			if data.Password == req.Password {
				isValid = true
				user = data
				break
			}
		}
	}
	if !isValid {
		return &pb.LoginResponse{}, status.Error(codes.Unauthenticated, "Invalid credentials data!")
	}

	token, err := uj.Encode(user)
	if err != nil {
		return &pb.LoginResponse{}, status.Error(codes.Internal, "Internal Server Error")
	}

	claim, err := uj.Verify(token)
	if err != nil {
		log.Printf("Error when verify the token.\nError: %s\n", err.Error())
	}
	extract := (claim["Data"]).(map[string]interface{})
	log.Println(extract["Name"])
	log.Println(extract)

	return &pb.LoginResponse{
		Token:    token,
		ExpireAt: time.Now().Add(time.Hour * 1).UnixNano(),
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", PORT)
	if err != nil {
		log.Fatalf("Cannot listen to port %s.\nError: %s\n", PORT, err.Error())
	}
	defer lis.Close()

	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(EnsureValidToken),
	}

	s := grpc.NewServer(opts...)
	pb.RegisterAuthServiceServer(s, &AuthServer{})
	log.Printf("Server is listening on port %s", lis.Addr().String())
	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("Cannot start GRPC Server on PORT %s.\nError: %s\n", PORT, err.Error())
	}
}
