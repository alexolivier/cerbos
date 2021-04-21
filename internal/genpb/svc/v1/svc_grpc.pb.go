// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package svcv1

import (
	context "context"
	v1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	v11 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// CerbosServiceClient is the client API for CerbosService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CerbosServiceClient interface {
	Check(ctx context.Context, in *v1.CheckRequest, opts ...grpc.CallOption) (*v11.CheckResponse, error)
	CheckResourceBatch(ctx context.Context, in *v1.CheckResourceBatchRequest, opts ...grpc.CallOption) (*v11.CheckResourceBatchResponse, error)
}

type cerbosServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCerbosServiceClient(cc grpc.ClientConnInterface) CerbosServiceClient {
	return &cerbosServiceClient{cc}
}

func (c *cerbosServiceClient) Check(ctx context.Context, in *v1.CheckRequest, opts ...grpc.CallOption) (*v11.CheckResponse, error) {
	out := new(v11.CheckResponse)
	err := c.cc.Invoke(ctx, "/svc.v1.CerbosService/Check", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cerbosServiceClient) CheckResourceBatch(ctx context.Context, in *v1.CheckResourceBatchRequest, opts ...grpc.CallOption) (*v11.CheckResourceBatchResponse, error) {
	out := new(v11.CheckResourceBatchResponse)
	err := c.cc.Invoke(ctx, "/svc.v1.CerbosService/CheckResourceBatch", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CerbosServiceServer is the server API for CerbosService service.
// All implementations must embed UnimplementedCerbosServiceServer
// for forward compatibility
type CerbosServiceServer interface {
	Check(context.Context, *v1.CheckRequest) (*v11.CheckResponse, error)
	CheckResourceBatch(context.Context, *v1.CheckResourceBatchRequest) (*v11.CheckResourceBatchResponse, error)
	mustEmbedUnimplementedCerbosServiceServer()
}

// UnimplementedCerbosServiceServer must be embedded to have forward compatible implementations.
type UnimplementedCerbosServiceServer struct {
}

func (UnimplementedCerbosServiceServer) Check(context.Context, *v1.CheckRequest) (*v11.CheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Check not implemented")
}
func (UnimplementedCerbosServiceServer) CheckResourceBatch(context.Context, *v1.CheckResourceBatchRequest) (*v11.CheckResourceBatchResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckResourceBatch not implemented")
}
func (UnimplementedCerbosServiceServer) mustEmbedUnimplementedCerbosServiceServer() {}

// UnsafeCerbosServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CerbosServiceServer will
// result in compilation errors.
type UnsafeCerbosServiceServer interface {
	mustEmbedUnimplementedCerbosServiceServer()
}

func RegisterCerbosServiceServer(s grpc.ServiceRegistrar, srv CerbosServiceServer) {
	s.RegisterService(&CerbosService_ServiceDesc, srv)
}

func _CerbosService_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v1.CheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CerbosServiceServer).Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/svc.v1.CerbosService/Check",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CerbosServiceServer).Check(ctx, req.(*v1.CheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CerbosService_CheckResourceBatch_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v1.CheckResourceBatchRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CerbosServiceServer).CheckResourceBatch(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/svc.v1.CerbosService/CheckResourceBatch",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CerbosServiceServer).CheckResourceBatch(ctx, req.(*v1.CheckResourceBatchRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CerbosService_ServiceDesc is the grpc.ServiceDesc for CerbosService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CerbosService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "svc.v1.CerbosService",
	HandlerType: (*CerbosServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Check",
			Handler:    _CerbosService_Check_Handler,
		},
		{
			MethodName: "CheckResourceBatch",
			Handler:    _CerbosService_CheckResourceBatch_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "svc/v1/svc.proto",
}
