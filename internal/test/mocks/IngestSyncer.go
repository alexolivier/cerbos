// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	context "context"

	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"

	mock "github.com/stretchr/testify/mock"
)

// IngestSyncer is an autogenerated mock type for the IngestSyncer type
type IngestSyncer struct {
	mock.Mock
}

type IngestSyncer_Expecter struct {
	mock *mock.Mock
}

func (_m *IngestSyncer) EXPECT() *IngestSyncer_Expecter {
	return &IngestSyncer_Expecter{mock: &_m.Mock}
}

// Sync provides a mock function with given fields: _a0, _a1
func (_m *IngestSyncer) Sync(_a0 context.Context, _a1 *logsv1.IngestBatch) error {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Sync")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *logsv1.IngestBatch) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IngestSyncer_Sync_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Sync'
type IngestSyncer_Sync_Call struct {
	*mock.Call
}

// Sync is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *logsv1.IngestBatch
func (_e *IngestSyncer_Expecter) Sync(_a0 interface{}, _a1 interface{}) *IngestSyncer_Sync_Call {
	return &IngestSyncer_Sync_Call{Call: _e.mock.On("Sync", _a0, _a1)}
}

func (_c *IngestSyncer_Sync_Call) Run(run func(_a0 context.Context, _a1 *logsv1.IngestBatch)) *IngestSyncer_Sync_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*logsv1.IngestBatch))
	})
	return _c
}

func (_c *IngestSyncer_Sync_Call) Return(_a0 error) *IngestSyncer_Sync_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IngestSyncer_Sync_Call) RunAndReturn(run func(context.Context, *logsv1.IngestBatch) error) *IngestSyncer_Sync_Call {
	_c.Call.Return(run)
	return _c
}

// NewIngestSyncer creates a new instance of IngestSyncer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIngestSyncer(t interface {
	mock.TestingT
	Cleanup(func())
}) *IngestSyncer {
	mock := &IngestSyncer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
