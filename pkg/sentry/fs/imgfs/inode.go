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
	"fmt"
	"io"
	"os"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/safemem"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)
// inodeOperations implements fs.InodeOperations for an fs.Inodes backed
// by a host file descriptor.
//
// +stateify savable
type fileInodeOperations struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotDirectory   `state:"nosave"`
	fsutil.InodeNotSocket      `state:"nosave"`
	fsutil.InodeNotSymlink     `state:"nosave"`

	fsutil.InodeSimpleExtendedAttributes

	attr fs.UnstableAttr

	mappings memmap.MappingSet

	mapArea []byte
	offsetBegin int64
	offsetEnd int64

	packageFD int
}

type Symlink struct {
	ramfs.Symlink
}

type ImgReader struct {
	f *fileInodeOperations
	offset int64
}

func NewImgReader(f *fileInodeOperations, offset int64) *ImgReader {
	return &ImgReader{f, offset}
}

func (r *ImgReader) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	if r.offset >= r.f.attr.Size {
		return 0, io.EOF
	}
	end := fs.ReadEndOffset(r.offset, int64(dsts.NumBytes()), r.f.attr.Size)
	if end == r.offset {
		return 0, nil
	}
	src := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(r.f.mapArea[r.f.offsetBegin + r.offset:r.f.offsetEnd]))
	n, err := safemem.CopySeq(dsts, src)
	return n, err
}

var fsInfo = fs.Info{
	Type: linux.TMPFS_MAGIC,

	// TODO: fsInfo is not correctly implemented for ImgFS
	TotalBlocks: 0,
	FreeBlocks:  0,
}

func (f *fileInodeOperations) Release(context.Context) {}

// Mappable implements fs.InodeOperations.Mappable.
func (f *fileInodeOperations) Mappable(*fs.Inode) memmap.Mappable {
	return f
}

// Rename implements fs.InodeOperations.Rename.
func (*fileInodeOperations) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return syserror.EPERM
}

// GetFile implements fs.InodeOperations.GetFile.
func (f *fileInodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	flags.Pread = true
	flags.Pwrite = true
	return fs.NewFile(ctx, d, flags, &regularFileOperations{iops: f}), nil
}

// UnstableAttr returns unstable attributes of this tmpfs file.
// TODO: fix this
func (f *fileInodeOperations) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	return f.attr, nil
}

// Check implements fs.InodeOperations.Check.
func (f *fileInodeOperations) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (f *fileInodeOperations) SetPermissions(ctx context.Context, _ *fs.Inode, p fs.FilePermissions) bool {
	return false
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (f *fileInodeOperations) SetTimestamps(ctx context.Context, _ *fs.Inode, ts fs.TimeSpec) error {
	return syserror.EPERM
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (f *fileInodeOperations) SetOwner(ctx context.Context, _ *fs.Inode, owner fs.FileOwner) error {
	return syserror.EPERM
}

func (f *fileInodeOperations) Truncate(ctx context.Context, _ *fs.Inode, size int64) error {
	return syserror.EPERM
}

// AddLink implements fs.InodeOperations.AddLink.
func (f *fileInodeOperations) AddLink() {}

// DropLink implements fs.InodeOperations.DropLink.
func (f *fileInodeOperations) DropLink() {}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
func (f *fileInodeOperations) NotifyStatusChange(ctx context.Context) {}

// IsVirtual implements fs.InodeOperations.IsVirtual.
func (*fileInodeOperations) IsVirtual() bool {
	return true
}

// StatFS implements fs.InodeOperations.StatFS.
// TODO: fix fsInfo
func (*fileInodeOperations) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}

func (f *fileInodeOperations) read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	size := f.attr.Size

	if offset >= size {
		return 0, io.EOF
	}

	n, err := dst.CopyOutFrom(ctx, &ImgReader{f, offset})
	return n, err
}

// AddMapping implements memmap.Mappable.AddMapping.
// TODO: add mapping support
func (f *fileInodeOperations) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) error {
	// f.mappings.AddMapping(ms, ar, offset, false /* writeable */)
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (f *fileInodeOperations) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) {
	// f.mappings.RemoveMapping(ms, ar, offset, false /* writeable */)
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (f *fileInodeOperations) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, writable bool) error {
	// f.mappings.AddMapping(ctx, ms, dstAR, offset, false /* writeable */)
	return nil
}

// IncRef implements platform.File.IncRef.
func (f *fileInodeOperations) IncRef(fr platform.FileRange) {}

// DecRef implements platform.File.DecRef.
func (f *fileInodeOperations) DecRef(fr platform.FileRange) {}

func (f *fileInodeOperations) FD() int {
	return f.packageFD
}

func (f *fileInodeOperations) MapInternal(fr platform.FileRange, at usermem.AccessType) (safemem.BlockSeq, error) {
  const pagesize = uint64(4096)
	if !fr.WellFormed() || fr.Length() == 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}
	if at.Execute {
		return safemem.BlockSeq{}, syserror.EACCES
	}

	if f.offsetBegin < 0 || f.offsetEnd < 0 {
		panic(fmt.Sprintf("invalid file offset, don't mmap directory inode"))
	}

	unsafeBegin := uint64(f.offsetBegin) + fr.Start
	unsafeEnd := uint64(f.offsetBegin) + fr.End

	boundary := uint64(f.offsetEnd) &^ (pagesize - 1) + pagesize

	if unsafeBegin > boundary {
		return safemem.BlockSeq{}, syserror.EACCES
	}

	if unsafeEnd > boundary {
		unsafeEnd = boundary
		//panic(fmt.Sprintf("invalid unsafeEnd: %v, current boundary: %v, unsafeBegin: %v, unsafeEnd: %v, fr.Start: %v, fr.End: %v, f.offsetBegin: %v, f.offsetEnd: %v\n", unsafeEnd, boundary, unsafeBegin, unsafeEnd, fr.Start, fr.End, f.offsetBegin, f.offsetEnd))
	}

	/*
	if unsafeBegin > uint64(f.offsetEnd) {
		return safemem.BlockSeq{}, syserror.EACCES
	}

	if unsafeEnd > uint64(f.offsetEnd) {
		unsafeEnd = uint64(f.offsetEnd)
	}
	*/
	seq := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(f.mapArea[unsafeBegin:unsafeEnd]))
	return seq, nil
}

// Translate implements memmap.Mappable.Translate.
func (f *fileInodeOperations) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	return []memmap.Translation{
		{
			Source: optional,
			File:   f,
			Offset: optional.Start,
		},
	}, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (f *fileInodeOperations) InvalidateUnsavable(ctx context.Context) error {
	f.mappings.InvalidateAll(memmap.InvalidateOpts{})
	return nil
}

// newInode returns a new fs.Inode
func newInode(ctx context.Context, msrc *fs.MountSource, begin int64, end int64, modTime int64, mode os.FileMode, packageFD int, m []byte) (*fs.Inode, error) {
	sattr := stableAttr()
	uattr := unstableAttr(ctx, begin, end, modTime, mode)
	iops := &fileInodeOperations{
		attr:     uattr,
		mapArea:	m,
		offsetBegin:	begin,
		offsetEnd:		end,
		packageFD:    packageFD,
	}
	return fs.NewInode(iops, msrc, sattr), nil
}

// newSymlink returns a new fs.Inode
func newSymlink(ctx context.Context, msrc *fs.MountSource, target string) *fs.Inode {
	s := &Symlink{Symlink: *ramfs.NewSymlink(ctx, fs.RootOwner, target)}
	return fs.NewInode(s, msrc, fs.StableAttr{
		DeviceID:  imgfsFileDevice.DeviceID(),
		InodeID:   imgfsFileDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Symlink,
	})
}
