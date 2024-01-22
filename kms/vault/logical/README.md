# logical

Package logical is a generated GoMock package.

## Types

### type [Logical](logical.go#L12)

`type Logical interface { ... }`

Logical backend interface

### type [MockLogical](logical.mock.go#L16)

`type MockLogical struct { ... }`

MockLogical is a mock of Logical interface.

#### func [NewMockLogical](logical.mock.go#L27)

`func NewMockLogical(ctrl *gomock.Controller) *MockLogical`

NewMockLogical creates a new mock instance.

#### func (*MockLogical) [EXPECT](logical.mock.go#L34)

`func (m *MockLogical) EXPECT() *MockLogicalMockRecorder`

EXPECT returns an object that allows the caller to indicate expected use.

#### func (*MockLogical) [ReadWithContext](logical.mock.go#L39)

`func (m *MockLogical) ReadWithContext(arg0 context.Context, arg1 string) (*api.Secret, error)`

ReadWithContext mocks base method.

#### func (*MockLogical) [ReadWithDataWithContext](logical.mock.go#L54)

`func (m *MockLogical) ReadWithDataWithContext(arg0 context.Context, arg1 string, arg2 map[string][]string) (*api.Secret, error)`

ReadWithDataWithContext mocks base method.

#### func (*MockLogical) [WriteWithContext](logical.mock.go#L69)

`func (m *MockLogical) WriteWithContext(arg0 context.Context, arg1 string, arg2 map[string]interface{ ... }) (*api.Secret, error)`

WriteWithContext mocks base method.

### type [MockLogicalMockRecorder](logical.mock.go#L22)

`type MockLogicalMockRecorder struct { ... }`

MockLogicalMockRecorder is the mock recorder for MockLogical.

#### func (*MockLogicalMockRecorder) [ReadWithContext](logical.mock.go#L48)

`func (mr *MockLogicalMockRecorder) ReadWithContext(arg0, arg1 interface{ ... }) *gomock.Call`

ReadWithContext indicates an expected call of ReadWithContext.

#### func (*MockLogicalMockRecorder) [ReadWithDataWithContext](logical.mock.go#L63)

`func (mr *MockLogicalMockRecorder) ReadWithDataWithContext(arg0, arg1, arg2 interface{ ... }) *gomock.Call`

ReadWithDataWithContext indicates an expected call of ReadWithDataWithContext.

#### func (*MockLogicalMockRecorder) [WriteWithContext](logical.mock.go#L78)

`func (mr *MockLogicalMockRecorder) WriteWithContext(arg0, arg1, arg2 interface{ ... }) *gomock.Call`

WriteWithContext indicates an expected call of WriteWithContext.

