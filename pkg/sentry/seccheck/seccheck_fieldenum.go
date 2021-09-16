// Generated by go_fieldenum.

package seccheck

import "sync/atomic"

// A CloneField represents a field in CloneInfo.
type CloneField uint

// CloneFieldX represents CloneInfo field X.
const (
	CloneFieldCredentials CloneField = iota
	CloneFieldArgs
)

// CloneFields represents a set of fields in CloneInfo in a literal-friendly form.
// The zero value of CloneFields represents an empty set.
type CloneFields struct {
	Invoker TaskFields
	Credentials bool
	Args bool
	Created TaskFields
}

// CloneFieldSet represents a set of fields in CloneInfo in a compact form.
// The zero value of CloneFieldSet represents an empty set.
type CloneFieldSet struct {
	Invoker TaskFieldSet
	Created TaskFieldSet
	fields [1]uint32
}

// Contains returns true if f is present in the CloneFieldSet.
func (fs CloneFieldSet) Contains(f CloneField) bool {
	return fs.fields[0] & (uint32(1) << uint(f)) != 0
}

// Add adds f to the CloneFieldSet.
func (fs *CloneFieldSet) Add(f CloneField) {
	fs.fields[0] |= uint32(1) << uint(f)
}

// Remove removes f from the CloneFieldSet.
func (fs *CloneFieldSet) Remove(f CloneField) {
	fs.fields[0] &^= uint32(1) << uint(f)
}

// Load returns a copy of the CloneFieldSet.
// Load is safe to call concurrently with AddFieldsLoadable, but not Add or Remove.
func (fs *CloneFieldSet) Load() (copied CloneFieldSet) {
	copied.Invoker = fs.Invoker.Load()
	copied.Created = fs.Created.Load()
	copied.fields[0] = atomic.LoadUint32(&fs.fields[0])
	return
}

// AddFieldsLoadable adds the given fields to the CloneFieldSet.
// AddFieldsLoadable is safe to call concurrently with Load, but not other methods (including other calls to AddFieldsLoadable).
func (fs *CloneFieldSet) AddFieldsLoadable(fields CloneFields) {
	fs.Invoker.AddFieldsLoadable(fields.Invoker)
	fs.Created.AddFieldsLoadable(fields.Created)
	if fields.Credentials {
		atomic.StoreUint32(&fs.fields[0], fs.fields[0] | (uint32(1) << uint(CloneFieldCredentials)))
	}
	if fields.Args {
		atomic.StoreUint32(&fs.fields[0], fs.fields[0] | (uint32(1) << uint(CloneFieldArgs)))
	}
}

// A TaskField represents a field in TaskInfo.
type TaskField uint

// TaskFieldX represents TaskInfo field X.
const (
	TaskFieldThreadID TaskField = iota
	TaskFieldThreadStartTime
	TaskFieldThreadGroupID
	TaskFieldThreadGroupStartTime
)

// TaskFields represents a set of fields in TaskInfo in a literal-friendly form.
// The zero value of TaskFields represents an empty set.
type TaskFields struct {
	ThreadID bool
	ThreadStartTime bool
	ThreadGroupID bool
	ThreadGroupStartTime bool
}

// TaskFieldSet represents a set of fields in TaskInfo in a compact form.
// The zero value of TaskFieldSet represents an empty set.
type TaskFieldSet struct {
	fields [1]uint32
}

// Contains returns true if f is present in the TaskFieldSet.
func (fs TaskFieldSet) Contains(f TaskField) bool {
	return fs.fields[0] & (uint32(1) << uint(f)) != 0
}

// Add adds f to the TaskFieldSet.
func (fs *TaskFieldSet) Add(f TaskField) {
	fs.fields[0] |= uint32(1) << uint(f)
}

// Remove removes f from the TaskFieldSet.
func (fs *TaskFieldSet) Remove(f TaskField) {
	fs.fields[0] &^= uint32(1) << uint(f)
}

// Load returns a copy of the TaskFieldSet.
// Load is safe to call concurrently with AddFieldsLoadable, but not Add or Remove.
func (fs *TaskFieldSet) Load() (copied TaskFieldSet) {
	copied.fields[0] = atomic.LoadUint32(&fs.fields[0])
	return
}

// AddFieldsLoadable adds the given fields to the TaskFieldSet.
// AddFieldsLoadable is safe to call concurrently with Load, but not other methods (including other calls to AddFieldsLoadable).
func (fs *TaskFieldSet) AddFieldsLoadable(fields TaskFields) {
	if fields.ThreadID {
		atomic.StoreUint32(&fs.fields[0], fs.fields[0] | (uint32(1) << uint(TaskFieldThreadID)))
	}
	if fields.ThreadStartTime {
		atomic.StoreUint32(&fs.fields[0], fs.fields[0] | (uint32(1) << uint(TaskFieldThreadStartTime)))
	}
	if fields.ThreadGroupID {
		atomic.StoreUint32(&fs.fields[0], fs.fields[0] | (uint32(1) << uint(TaskFieldThreadGroupID)))
	}
	if fields.ThreadGroupStartTime {
		atomic.StoreUint32(&fs.fields[0], fs.fields[0] | (uint32(1) << uint(TaskFieldThreadGroupStartTime)))
	}
}
