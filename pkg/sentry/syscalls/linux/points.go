// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linux

import (
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func PointOpen(ctx context.Context, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Open{}
	addr := info.Args[0].Pointer()
	if addr > 0 {
		t := kernel.TaskFromContext(ctx)
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil {
			p.Pathname = path
		}
	}
	p.Flags = info.Args[1].Uint()
	p.Mode = uint32(info.Args[2].ModeT())
	p.Exit = seccheck.NewExitMaybe(info)
	return p
}

func PointRead(_ context.Context, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Read{
		Fd:    int64(info.Args[0].Int()),
		Count: uint64(info.Args[2].SizeT()),
	}
	p.Exit = seccheck.NewExitMaybe(info)
	return p
}
