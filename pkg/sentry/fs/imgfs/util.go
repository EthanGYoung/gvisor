// Copyright 2018 Google LLC
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

package imgfs

import (
	"os"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

func stableAttr() fs.StableAttr {
	return fs.StableAttr{
		Type:     fs.RegularFile,
		DeviceID: imgfsFileDevice.DeviceID(),
		InodeID: imgfsFileDevice.NextIno(),
		BlockSize: usermem.PageSize,
	}
}

func unstableAttr(ctx context.Context, offsetBegin int64, offsetEnd int64, unixTimens int64, mode os.FileMode) fs.UnstableAttr {
	return fs.UnstableAttr{
		Size:             offsetEnd - offsetBegin,
		Usage:            offsetEnd - offsetBegin,
		Perms:            fs.FilePermsFromMode(linux.FileMode(mode)),
		Owner:            fs.FileOwnerFromContext(ctx),
		AccessTime:       ktime.FromNanoseconds(unixTimens),
		ModificationTime: ktime.FromNanoseconds(unixTimens),
		StatusChangeTime: ktime.FromNanoseconds(unixTimens),
		Links:            1,
	}
}
