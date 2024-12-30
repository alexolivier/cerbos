// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	context "context"
	io "io"

	mock "github.com/stretchr/testify/mock"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"

	storage "github.com/cerbos/cerbos/internal/storage"
)

// Store is an autogenerated mock type for the Store type
type Store struct {
	mock.Mock
}

type Store_Expecter struct {
	mock *mock.Mock
}

func (_m *Store) EXPECT() *Store_Expecter {
	return &Store_Expecter{mock: &_m.Mock}
}

// Driver provides a mock function with no fields
func (_m *Store) Driver() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Driver")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Store_Driver_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Driver'
type Store_Driver_Call struct {
	*mock.Call
}

// Driver is a helper method to define mock.On call
func (_e *Store_Expecter) Driver() *Store_Driver_Call {
	return &Store_Driver_Call{Call: _e.mock.On("Driver")}
}

func (_c *Store_Driver_Call) Run(run func()) *Store_Driver_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Store_Driver_Call) Return(_a0 string) *Store_Driver_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Store_Driver_Call) RunAndReturn(run func() string) *Store_Driver_Call {
	_c.Call.Return(run)
	return _c
}

// InspectPolicies provides a mock function with given fields: _a0, _a1
func (_m *Store) InspectPolicies(_a0 context.Context, _a1 storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for InspectPolicies")
	}

	var r0 map[string]*responsev1.InspectPoliciesResponse_Result
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, storage.ListPolicyIDsParams) map[string]*responsev1.InspectPoliciesResponse_Result); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]*responsev1.InspectPoliciesResponse_Result)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, storage.ListPolicyIDsParams) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Store_InspectPolicies_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'InspectPolicies'
type Store_InspectPolicies_Call struct {
	*mock.Call
}

// InspectPolicies is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 storage.ListPolicyIDsParams
func (_e *Store_Expecter) InspectPolicies(_a0 interface{}, _a1 interface{}) *Store_InspectPolicies_Call {
	return &Store_InspectPolicies_Call{Call: _e.mock.On("InspectPolicies", _a0, _a1)}
}

func (_c *Store_InspectPolicies_Call) Run(run func(_a0 context.Context, _a1 storage.ListPolicyIDsParams)) *Store_InspectPolicies_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(storage.ListPolicyIDsParams))
	})
	return _c
}

func (_c *Store_InspectPolicies_Call) Return(_a0 map[string]*responsev1.InspectPoliciesResponse_Result, _a1 error) *Store_InspectPolicies_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Store_InspectPolicies_Call) RunAndReturn(run func(context.Context, storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error)) *Store_InspectPolicies_Call {
	_c.Call.Return(run)
	return _c
}

// ListPolicyIDs provides a mock function with given fields: _a0, _a1
func (_m *Store) ListPolicyIDs(_a0 context.Context, _a1 storage.ListPolicyIDsParams) ([]string, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ListPolicyIDs")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, storage.ListPolicyIDsParams) ([]string, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, storage.ListPolicyIDsParams) []string); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, storage.ListPolicyIDsParams) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Store_ListPolicyIDs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListPolicyIDs'
type Store_ListPolicyIDs_Call struct {
	*mock.Call
}

// ListPolicyIDs is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 storage.ListPolicyIDsParams
func (_e *Store_Expecter) ListPolicyIDs(_a0 interface{}, _a1 interface{}) *Store_ListPolicyIDs_Call {
	return &Store_ListPolicyIDs_Call{Call: _e.mock.On("ListPolicyIDs", _a0, _a1)}
}

func (_c *Store_ListPolicyIDs_Call) Run(run func(_a0 context.Context, _a1 storage.ListPolicyIDsParams)) *Store_ListPolicyIDs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(storage.ListPolicyIDsParams))
	})
	return _c
}

func (_c *Store_ListPolicyIDs_Call) Return(_a0 []string, _a1 error) *Store_ListPolicyIDs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Store_ListPolicyIDs_Call) RunAndReturn(run func(context.Context, storage.ListPolicyIDsParams) ([]string, error)) *Store_ListPolicyIDs_Call {
	_c.Call.Return(run)
	return _c
}

// ListSchemaIDs provides a mock function with given fields: _a0
func (_m *Store) ListSchemaIDs(_a0 context.Context) ([]string, error) {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for ListSchemaIDs")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]string, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []string); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Store_ListSchemaIDs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListSchemaIDs'
type Store_ListSchemaIDs_Call struct {
	*mock.Call
}

// ListSchemaIDs is a helper method to define mock.On call
//   - _a0 context.Context
func (_e *Store_Expecter) ListSchemaIDs(_a0 interface{}) *Store_ListSchemaIDs_Call {
	return &Store_ListSchemaIDs_Call{Call: _e.mock.On("ListSchemaIDs", _a0)}
}

func (_c *Store_ListSchemaIDs_Call) Run(run func(_a0 context.Context)) *Store_ListSchemaIDs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *Store_ListSchemaIDs_Call) Return(_a0 []string, _a1 error) *Store_ListSchemaIDs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Store_ListSchemaIDs_Call) RunAndReturn(run func(context.Context) ([]string, error)) *Store_ListSchemaIDs_Call {
	_c.Call.Return(run)
	return _c
}

// LoadSchema provides a mock function with given fields: _a0, _a1
func (_m *Store) LoadSchema(_a0 context.Context, _a1 string) (io.ReadCloser, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for LoadSchema")
	}

	var r0 io.ReadCloser
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (io.ReadCloser, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) io.ReadCloser); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.ReadCloser)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Store_LoadSchema_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LoadSchema'
type Store_LoadSchema_Call struct {
	*mock.Call
}

// LoadSchema is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 string
func (_e *Store_Expecter) LoadSchema(_a0 interface{}, _a1 interface{}) *Store_LoadSchema_Call {
	return &Store_LoadSchema_Call{Call: _e.mock.On("LoadSchema", _a0, _a1)}
}

func (_c *Store_LoadSchema_Call) Run(run func(_a0 context.Context, _a1 string)) *Store_LoadSchema_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Store_LoadSchema_Call) Return(_a0 io.ReadCloser, _a1 error) *Store_LoadSchema_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Store_LoadSchema_Call) RunAndReturn(run func(context.Context, string) (io.ReadCloser, error)) *Store_LoadSchema_Call {
	_c.Call.Return(run)
	return _c
}

// NewStore creates a new instance of Store. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStore(t interface {
	mock.TestingT
	Cleanup(func())
}) *Store {
	mock := &Store{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
