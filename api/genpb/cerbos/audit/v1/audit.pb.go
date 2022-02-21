// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        (unknown)
// source: cerbos/audit/v1/audit.proto

package auditv1

import (
	v1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AccessLogEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CallId     string                 `protobuf:"bytes,1,opt,name=call_id,json=callId,proto3" json:"call_id,omitempty"`
	Timestamp  *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Peer       *Peer                  `protobuf:"bytes,3,opt,name=peer,proto3" json:"peer,omitempty"`
	Metadata   map[string]*MetaValues `protobuf:"bytes,4,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Method     string                 `protobuf:"bytes,5,opt,name=method,proto3" json:"method,omitempty"`
	StatusCode uint32                 `protobuf:"varint,6,opt,name=status_code,json=statusCode,proto3" json:"status_code,omitempty"`
}

func (x *AccessLogEntry) Reset() {
	*x = AccessLogEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cerbos_audit_v1_audit_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessLogEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessLogEntry) ProtoMessage() {}

func (x *AccessLogEntry) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_audit_v1_audit_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessLogEntry.ProtoReflect.Descriptor instead.
func (*AccessLogEntry) Descriptor() ([]byte, []int) {
	return file_cerbos_audit_v1_audit_proto_rawDescGZIP(), []int{0}
}

func (x *AccessLogEntry) GetCallId() string {
	if x != nil {
		return x.CallId
	}
	return ""
}

func (x *AccessLogEntry) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *AccessLogEntry) GetPeer() *Peer {
	if x != nil {
		return x.Peer
	}
	return nil
}

func (x *AccessLogEntry) GetMetadata() map[string]*MetaValues {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *AccessLogEntry) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *AccessLogEntry) GetStatusCode() uint32 {
	if x != nil {
		return x.StatusCode
	}
	return 0
}

type DecisionLogEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CallId    string                 `protobuf:"bytes,1,opt,name=call_id,json=callId,proto3" json:"call_id,omitempty"`
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Peer      *Peer                  `protobuf:"bytes,3,opt,name=peer,proto3" json:"peer,omitempty"`
	Inputs    []*v1.CheckInput       `protobuf:"bytes,4,rep,name=inputs,proto3" json:"inputs,omitempty"`
	Outputs   []*v1.CheckOutput      `protobuf:"bytes,5,rep,name=outputs,proto3" json:"outputs,omitempty"`
	Error     string                 `protobuf:"bytes,6,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *DecisionLogEntry) Reset() {
	*x = DecisionLogEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cerbos_audit_v1_audit_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DecisionLogEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecisionLogEntry) ProtoMessage() {}

func (x *DecisionLogEntry) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_audit_v1_audit_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DecisionLogEntry.ProtoReflect.Descriptor instead.
func (*DecisionLogEntry) Descriptor() ([]byte, []int) {
	return file_cerbos_audit_v1_audit_proto_rawDescGZIP(), []int{1}
}

func (x *DecisionLogEntry) GetCallId() string {
	if x != nil {
		return x.CallId
	}
	return ""
}

func (x *DecisionLogEntry) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *DecisionLogEntry) GetPeer() *Peer {
	if x != nil {
		return x.Peer
	}
	return nil
}

func (x *DecisionLogEntry) GetInputs() []*v1.CheckInput {
	if x != nil {
		return x.Inputs
	}
	return nil
}

func (x *DecisionLogEntry) GetOutputs() []*v1.CheckOutput {
	if x != nil {
		return x.Outputs
	}
	return nil
}

func (x *DecisionLogEntry) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

type MetaValues struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Values []string `protobuf:"bytes,1,rep,name=values,proto3" json:"values,omitempty"`
}

func (x *MetaValues) Reset() {
	*x = MetaValues{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cerbos_audit_v1_audit_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetaValues) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetaValues) ProtoMessage() {}

func (x *MetaValues) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_audit_v1_audit_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetaValues.ProtoReflect.Descriptor instead.
func (*MetaValues) Descriptor() ([]byte, []int) {
	return file_cerbos_audit_v1_audit_proto_rawDescGZIP(), []int{2}
}

func (x *MetaValues) GetValues() []string {
	if x != nil {
		return x.Values
	}
	return nil
}

type Peer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address      string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	AuthInfo     string `protobuf:"bytes,2,opt,name=auth_info,json=authInfo,proto3" json:"auth_info,omitempty"`
	UserAgent    string `protobuf:"bytes,3,opt,name=user_agent,json=userAgent,proto3" json:"user_agent,omitempty"`
	ForwardedFor string `protobuf:"bytes,4,opt,name=forwarded_for,json=forwardedFor,proto3" json:"forwarded_for,omitempty"`
}

func (x *Peer) Reset() {
	*x = Peer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cerbos_audit_v1_audit_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Peer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Peer) ProtoMessage() {}

func (x *Peer) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_audit_v1_audit_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Peer.ProtoReflect.Descriptor instead.
func (*Peer) Descriptor() ([]byte, []int) {
	return file_cerbos_audit_v1_audit_proto_rawDescGZIP(), []int{3}
}

func (x *Peer) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Peer) GetAuthInfo() string {
	if x != nil {
		return x.AuthInfo
	}
	return ""
}

func (x *Peer) GetUserAgent() string {
	if x != nil {
		return x.UserAgent
	}
	return ""
}

func (x *Peer) GetForwardedFor() string {
	if x != nil {
		return x.ForwardedFor
	}
	return ""
}

var File_cerbos_audit_v1_audit_proto protoreflect.FileDescriptor

var file_cerbos_audit_v1_audit_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2f, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2f, 0x76,
	0x31, 0x2f, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x63,
	0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1d, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2f, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xec,
	0x02, 0x0a, 0x0e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x6f, 0x67, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x17, 0x0a, 0x07, 0x63, 0x61, 0x6c, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x63, 0x61, 0x6c, 0x6c, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x09, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x12, 0x29, 0x0a, 0x04, 0x70, 0x65, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x15, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x64, 0x69,
	0x74, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x65, 0x65, 0x72, 0x52, 0x04, 0x70, 0x65, 0x65, 0x72, 0x12,
	0x49, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x64, 0x69, 0x74,
	0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x6f, 0x67, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x16, 0x0a, 0x06, 0x6d, 0x65,
	0x74, 0x68, 0x6f, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6d, 0x65, 0x74, 0x68,
	0x6f, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x63, 0x6f, 0x64,
	0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x43,
	0x6f, 0x64, 0x65, 0x1a, 0x58, 0x0a, 0x0d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x31, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x61,
	0x75, 0x64, 0x69, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x73, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x95, 0x02,
	0x0a, 0x10, 0x44, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x4c, 0x6f, 0x67, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x17, 0x0a, 0x07, 0x63, 0x61, 0x6c, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x63, 0x61, 0x6c, 0x6c, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x09, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x29, 0x0a, 0x04, 0x70, 0x65, 0x65, 0x72, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x64,
	0x69, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x65, 0x65, 0x72, 0x52, 0x04, 0x70, 0x65, 0x65, 0x72,
	0x12, 0x34, 0x0a, 0x06, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x1c, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x52, 0x06,
	0x69, 0x6e, 0x70, 0x75, 0x74, 0x73, 0x12, 0x37, 0x0a, 0x07, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74,
	0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73,
	0x2e, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b,
	0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x52, 0x07, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x73, 0x12,
	0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x65, 0x72, 0x72, 0x6f, 0x72, 0x22, 0x24, 0x0a, 0x0a, 0x4d, 0x65, 0x74, 0x61, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x22, 0x81, 0x01, 0x0a, 0x04,
	0x50, 0x65, 0x65, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1b,
	0x0a, 0x09, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x61, 0x75, 0x74, 0x68, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1d, 0x0a, 0x0a, 0x75,
	0x73, 0x65, 0x72, 0x5f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x75, 0x73, 0x65, 0x72, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x23, 0x0a, 0x0d, 0x66, 0x6f,
	0x72, 0x77, 0x61, 0x72, 0x64, 0x65, 0x64, 0x5f, 0x66, 0x6f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0c, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x65, 0x64, 0x46, 0x6f, 0x72, 0x42,
	0x6b, 0x0a, 0x17, 0x64, 0x65, 0x76, 0x2e, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x76, 0x31, 0x2e, 0x61, 0x75, 0x64, 0x69, 0x74, 0x5a, 0x3a, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2f, 0x63, 0x65,
	0x72, 0x62, 0x6f, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x70, 0x62, 0x2f, 0x63,
	0x65, 0x72, 0x62, 0x6f, 0x73, 0x2f, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x61,
	0x75, 0x64, 0x69, 0x74, 0x76, 0x31, 0xaa, 0x02, 0x13, 0x43, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x2e,
	0x41, 0x70, 0x69, 0x2e, 0x56, 0x31, 0x2e, 0x41, 0x75, 0x64, 0x69, 0x74, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cerbos_audit_v1_audit_proto_rawDescOnce sync.Once
	file_cerbos_audit_v1_audit_proto_rawDescData = file_cerbos_audit_v1_audit_proto_rawDesc
)

func file_cerbos_audit_v1_audit_proto_rawDescGZIP() []byte {
	file_cerbos_audit_v1_audit_proto_rawDescOnce.Do(func() {
		file_cerbos_audit_v1_audit_proto_rawDescData = protoimpl.X.CompressGZIP(file_cerbos_audit_v1_audit_proto_rawDescData)
	})
	return file_cerbos_audit_v1_audit_proto_rawDescData
}

var file_cerbos_audit_v1_audit_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_cerbos_audit_v1_audit_proto_goTypes = []interface{}{
	(*AccessLogEntry)(nil),        // 0: cerbos.audit.v1.AccessLogEntry
	(*DecisionLogEntry)(nil),      // 1: cerbos.audit.v1.DecisionLogEntry
	(*MetaValues)(nil),            // 2: cerbos.audit.v1.MetaValues
	(*Peer)(nil),                  // 3: cerbos.audit.v1.Peer
	nil,                           // 4: cerbos.audit.v1.AccessLogEntry.MetadataEntry
	(*timestamppb.Timestamp)(nil), // 5: google.protobuf.Timestamp
	(*v1.CheckInput)(nil),         // 6: cerbos.engine.v1.CheckInput
	(*v1.CheckOutput)(nil),        // 7: cerbos.engine.v1.CheckOutput
}
var file_cerbos_audit_v1_audit_proto_depIdxs = []int32{
	5, // 0: cerbos.audit.v1.AccessLogEntry.timestamp:type_name -> google.protobuf.Timestamp
	3, // 1: cerbos.audit.v1.AccessLogEntry.peer:type_name -> cerbos.audit.v1.Peer
	4, // 2: cerbos.audit.v1.AccessLogEntry.metadata:type_name -> cerbos.audit.v1.AccessLogEntry.MetadataEntry
	5, // 3: cerbos.audit.v1.DecisionLogEntry.timestamp:type_name -> google.protobuf.Timestamp
	3, // 4: cerbos.audit.v1.DecisionLogEntry.peer:type_name -> cerbos.audit.v1.Peer
	6, // 5: cerbos.audit.v1.DecisionLogEntry.inputs:type_name -> cerbos.engine.v1.CheckInput
	7, // 6: cerbos.audit.v1.DecisionLogEntry.outputs:type_name -> cerbos.engine.v1.CheckOutput
	2, // 7: cerbos.audit.v1.AccessLogEntry.MetadataEntry.value:type_name -> cerbos.audit.v1.MetaValues
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_cerbos_audit_v1_audit_proto_init() }
func file_cerbos_audit_v1_audit_proto_init() {
	if File_cerbos_audit_v1_audit_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cerbos_audit_v1_audit_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessLogEntry); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_cerbos_audit_v1_audit_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DecisionLogEntry); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_cerbos_audit_v1_audit_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetaValues); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_cerbos_audit_v1_audit_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Peer); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cerbos_audit_v1_audit_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cerbos_audit_v1_audit_proto_goTypes,
		DependencyIndexes: file_cerbos_audit_v1_audit_proto_depIdxs,
		MessageInfos:      file_cerbos_audit_v1_audit_proto_msgTypes,
	}.Build()
	File_cerbos_audit_v1_audit_proto = out.File
	file_cerbos_audit_v1_audit_proto_rawDesc = nil
	file_cerbos_audit_v1_audit_proto_goTypes = nil
	file_cerbos_audit_v1_audit_proto_depIdxs = nil
}
