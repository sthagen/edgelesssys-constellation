// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.29.0--rc2
// source: verify/verifyproto/verify.proto

package verifyproto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetAttestationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Nonce []byte `protobuf:"bytes,2,opt,name=nonce,proto3" json:"nonce,omitempty"`
}

func (x *GetAttestationRequest) Reset() {
	*x = GetAttestationRequest{}
	mi := &file_verify_verifyproto_verify_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetAttestationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAttestationRequest) ProtoMessage() {}

func (x *GetAttestationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_verify_verifyproto_verify_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAttestationRequest.ProtoReflect.Descriptor instead.
func (*GetAttestationRequest) Descriptor() ([]byte, []int) {
	return file_verify_verifyproto_verify_proto_rawDescGZIP(), []int{0}
}

func (x *GetAttestationRequest) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

type GetAttestationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Attestation []byte `protobuf:"bytes,1,opt,name=attestation,proto3" json:"attestation,omitempty"`
}

func (x *GetAttestationResponse) Reset() {
	*x = GetAttestationResponse{}
	mi := &file_verify_verifyproto_verify_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetAttestationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAttestationResponse) ProtoMessage() {}

func (x *GetAttestationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_verify_verifyproto_verify_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAttestationResponse.ProtoReflect.Descriptor instead.
func (*GetAttestationResponse) Descriptor() ([]byte, []int) {
	return file_verify_verifyproto_verify_proto_rawDescGZIP(), []int{1}
}

func (x *GetAttestationResponse) GetAttestation() []byte {
	if x != nil {
		return x.Attestation
	}
	return nil
}

var File_verify_verifyproto_verify_proto protoreflect.FileDescriptor

var file_verify_verifyproto_verify_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x2f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x06, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x22, 0x2d, 0x0a, 0x15, 0x47, 0x65, 0x74,
	0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x22, 0x3a, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x41,
	0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x32, 0x56, 0x0a, 0x03, 0x41, 0x50, 0x49, 0x12, 0x4f, 0x0a, 0x0e, 0x47,
	0x65, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x2e,
	0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x76,
	0x65, 0x72, 0x69, 0x66, 0x79, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x3c, 0x5a, 0x3a,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x64, 0x67, 0x65, 0x6c,
	0x65, 0x73, 0x73, 0x73, 0x79, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x65, 0x6c, 0x6c, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x32, 0x2f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x2f, 0x76,
	0x65, 0x72, 0x69, 0x66, 0x79, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_verify_verifyproto_verify_proto_rawDescOnce sync.Once
	file_verify_verifyproto_verify_proto_rawDescData = file_verify_verifyproto_verify_proto_rawDesc
)

func file_verify_verifyproto_verify_proto_rawDescGZIP() []byte {
	file_verify_verifyproto_verify_proto_rawDescOnce.Do(func() {
		file_verify_verifyproto_verify_proto_rawDescData = protoimpl.X.CompressGZIP(file_verify_verifyproto_verify_proto_rawDescData)
	})
	return file_verify_verifyproto_verify_proto_rawDescData
}

var file_verify_verifyproto_verify_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_verify_verifyproto_verify_proto_goTypes = []any{
	(*GetAttestationRequest)(nil),  // 0: verify.GetAttestationRequest
	(*GetAttestationResponse)(nil), // 1: verify.GetAttestationResponse
}
var file_verify_verifyproto_verify_proto_depIdxs = []int32{
	0, // 0: verify.API.GetAttestation:input_type -> verify.GetAttestationRequest
	1, // 1: verify.API.GetAttestation:output_type -> verify.GetAttestationResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_verify_verifyproto_verify_proto_init() }
func file_verify_verifyproto_verify_proto_init() {
	if File_verify_verifyproto_verify_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_verify_verifyproto_verify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_verify_verifyproto_verify_proto_goTypes,
		DependencyIndexes: file_verify_verifyproto_verify_proto_depIdxs,
		MessageInfos:      file_verify_verifyproto_verify_proto_msgTypes,
	}.Build()
	File_verify_verifyproto_verify_proto = out.File
	file_verify_verifyproto_verify_proto_rawDesc = nil
	file_verify_verifyproto_verify_proto_goTypes = nil
	file_verify_verifyproto_verify_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// APIClient is the client API for API service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type APIClient interface {
	GetAttestation(ctx context.Context, in *GetAttestationRequest, opts ...grpc.CallOption) (*GetAttestationResponse, error)
}

type aPIClient struct {
	cc grpc.ClientConnInterface
}

func NewAPIClient(cc grpc.ClientConnInterface) APIClient {
	return &aPIClient{cc}
}

func (c *aPIClient) GetAttestation(ctx context.Context, in *GetAttestationRequest, opts ...grpc.CallOption) (*GetAttestationResponse, error) {
	out := new(GetAttestationResponse)
	err := c.cc.Invoke(ctx, "/verify.API/GetAttestation", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// APIServer is the server API for API service.
type APIServer interface {
	GetAttestation(context.Context, *GetAttestationRequest) (*GetAttestationResponse, error)
}

// UnimplementedAPIServer can be embedded to have forward compatible implementations.
type UnimplementedAPIServer struct {
}

func (*UnimplementedAPIServer) GetAttestation(context.Context, *GetAttestationRequest) (*GetAttestationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAttestation not implemented")
}

func RegisterAPIServer(s *grpc.Server, srv APIServer) {
	s.RegisterService(&_API_serviceDesc, srv)
}

func _API_GetAttestation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAttestationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).GetAttestation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verify.API/GetAttestation",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).GetAttestation(ctx, req.(*GetAttestationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _API_serviceDesc = grpc.ServiceDesc{
	ServiceName: "verify.API",
	HandlerType: (*APIServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAttestation",
			Handler:    _API_GetAttestation_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "verify/verifyproto/verify.proto",
}
