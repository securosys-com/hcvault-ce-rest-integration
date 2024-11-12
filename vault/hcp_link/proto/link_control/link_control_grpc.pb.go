// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: vault/hcp_link/proto/link_control/link_control.proto

package link_control

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	HCPLinkControl_PurgePolicy_FullMethodName = "/link_control.HCPLinkControl/PurgePolicy"
)

// HCPLinkControlClient is the client API for HCPLinkControl service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type HCPLinkControlClient interface {
	// PurgePolicy Forgets the current Batch token, and its associated policy,
	// such that the policy is forced to be refreshed.
	PurgePolicy(ctx context.Context, in *PurgePolicyRequest, opts ...grpc.CallOption) (*PurgePolicyResponse, error)
}

type hCPLinkControlClient struct {
	cc grpc.ClientConnInterface
}

func NewHCPLinkControlClient(cc grpc.ClientConnInterface) HCPLinkControlClient {
	return &hCPLinkControlClient{cc}
}

func (c *hCPLinkControlClient) PurgePolicy(ctx context.Context, in *PurgePolicyRequest, opts ...grpc.CallOption) (*PurgePolicyResponse, error) {
	out := new(PurgePolicyResponse)
	err := c.cc.Invoke(ctx, HCPLinkControl_PurgePolicy_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HCPLinkControlServer is the server API for HCPLinkControl service.
// All implementations must embed UnimplementedHCPLinkControlServer
// for forward compatibility
type HCPLinkControlServer interface {
	// PurgePolicy Forgets the current Batch token, and its associated policy,
	// such that the policy is forced to be refreshed.
	PurgePolicy(context.Context, *PurgePolicyRequest) (*PurgePolicyResponse, error)
	mustEmbedUnimplementedHCPLinkControlServer()
}

// UnimplementedHCPLinkControlServer must be embedded to have forward compatible implementations.
type UnimplementedHCPLinkControlServer struct {
}

func (UnimplementedHCPLinkControlServer) PurgePolicy(context.Context, *PurgePolicyRequest) (*PurgePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PurgePolicy not implemented")
}
func (UnimplementedHCPLinkControlServer) mustEmbedUnimplementedHCPLinkControlServer() {}

// UnsafeHCPLinkControlServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to HCPLinkControlServer will
// result in compilation errors.
type UnsafeHCPLinkControlServer interface {
	mustEmbedUnimplementedHCPLinkControlServer()
}

func RegisterHCPLinkControlServer(s grpc.ServiceRegistrar, srv HCPLinkControlServer) {
	s.RegisterService(&HCPLinkControl_ServiceDesc, srv)
}

func _HCPLinkControl_PurgePolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PurgePolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HCPLinkControlServer).PurgePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: HCPLinkControl_PurgePolicy_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HCPLinkControlServer).PurgePolicy(ctx, req.(*PurgePolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// HCPLinkControl_ServiceDesc is the grpc.ServiceDesc for HCPLinkControl service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var HCPLinkControl_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "link_control.HCPLinkControl",
	HandlerType: (*HCPLinkControlServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PurgePolicy",
			Handler:    _HCPLinkControl_PurgePolicy_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "vault/hcp_link/proto/link_control/link_control.proto",
}
