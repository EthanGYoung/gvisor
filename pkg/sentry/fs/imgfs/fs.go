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

// Package host implements an fs.Filesystem for files backed by host
// file descriptors.
package imgfs

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// FilesystemName is the name under which Filesystem is registered.
const FilesystemName = "imgfs"

const (
	// packageFDKey is the mount option containing an int of package FD
	packageFDKey = "packageFD"
)

// Filesystem is a pseudo file system that is only available during the setup
// to lock down the configurations. This filesystem should only be mounted at root.
//
// Think twice before exposing this to applications.
//
// +stateify savable
type Filesystem struct {
	// whitelist is a set of host paths to whitelist.
	packageFD int
}

type fileType int

const(
	ImgFSRegularFile fileType = iota
	ImgFSDirectory
	ImgFSSymlink
	ImgFSWhiteoutFile
)

type fileMetadata struct {
	Begin int64
	End int64
	Name string
	Link string
	ModTime int64
	Type fileType
	Mode os.FileMode
}

var _ fs.Filesystem = (*Filesystem)(nil)

// Name is the identifier of this file system.
func (*Filesystem) Name() string {
	return FilesystemName
}

// AllowUserMount prohibits users from using mount(2) with this file system.
func (*Filesystem) AllowUserMount() bool {
	return false
}

// AllowUserList allows this filesystem to be listed in /proc/filesystems.
func (*Filesystem) AllowUserList() bool {
	return true
}

// Flags returns that there is nothing special about this file system.
func (*Filesystem) Flags() fs.FilesystemFlags {
	return 0
}

// Mount returns an fs.Inode exposing the host file system.  It is intended to be locked
// down in PreExec below.
func (f *Filesystem) Mount(ctx context.Context, _ string, flags fs.MountSourceFlags, data string, _ interface{}) (*fs.Inode, error) {
	// Parse generic comma-separated key=value options.
	options := fs.GenericMountSourceOptions(data)

	// Grab the packageFD if one was specified.
	if packageFD, ok := options[packageFDKey]; ok {
		v, err := strconv.ParseInt(packageFD, 10, 32)
		if (err != nil) {
			return nil, fmt.Errorf("cannot convert packageFD id to int: %v", err)
		}
		f.packageFD = int(v)
		delete(options, packageFDKey)
	}

	if (f.packageFD <= 0) {
		return nil, fmt.Errorf("invalid packageFD when mounting imgfs: %v", f.packageFD)
	}

	log.Infof("imgfs.packageFD: %v", f.packageFD)

	// Fail if the caller passed us more options than we know about.
	if len(options) > 0 {
		return nil, fmt.Errorf("unsupported mount options: %v", options)
	}

	// Construct img file system mount and inode.
	msrc := fs.NewCachingMountSource(f, flags)

	var s syscall.Stat_t
	err := syscall.Fstat(int(f.packageFD), &s)
	if err != nil {
		return nil, fmt.Errorf("unable to stat package file: %v", err)
	}
	log.Infof("stat package file size: %v", s.Size)
	length := int(s.Size)
    if length == 0 {
        return nil, fmt.Errorf("the image file size shouldn't be zero")
    }
	// mmap, err := syscall.Mmap(int(f.packageFD), 0, length, syscall.PROT_READ|syscall.PROT_EXEC, syscall.MAP_SHARED)
	mmap, err := syscall.Mmap(int(f.packageFD), 0, length, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
        return nil, fmt.Errorf("can't mmap the package image file, packageFD: %v, length: %v, err: %v", int(f.packageFD), length, err)
	}
	headerLoc := mmap[length - 10 : length]
	headerReader := bytes.NewReader(headerLoc)
	n, err := binary.ReadVarint(headerReader)
	if err != nil {
		return nil, fmt.Errorf("can't read header location, err: %v", err)
	}
	header := mmap[int(n) : length - 10]
	metadataReader := bytes.NewReader(header)
	var metadata []fileMetadata
	dec := gob.NewDecoder(metadataReader)
	errDec := dec.Decode(&metadata)
	if errDec != nil {
		  return nil, fmt.Errorf("can't decode metadata data, err: %v", errDec)
	}

	i := 0
	return MountImgRecursive(ctx, msrc, metadata, os.ModeDir | 0555, mmap, f.packageFD, &i, len(metadata))
}

func MountImgRecursive(ctx context.Context, msrc *fs.MountSource, metadata []fileMetadata, dirMode os.FileMode, mmap []byte, packageFD int, i *int, length int) (*fs.Inode, error) {
	contents := map[string]*fs.Inode{}
	var whitoutFiles []string
	for *i < length {
		offsetBegin := metadata[*i].Begin
		offsetEnd := metadata[*i].End
		fileName := metadata[*i].Name
		fileType := metadata[*i].Type
		fileModTime := metadata[*i].ModTime
		fileMode := metadata[*i].Mode

		if fileType == ImgFSRegularFile {
			inode, err := newInode(ctx, msrc, offsetBegin, offsetEnd, fileModTime, fileMode, packageFD, mmap)
			if err != nil {
				return nil, fmt.Errorf("can't create inode file %v, err: %v", fileName, err)
			}
			contents[fileName] = inode
			*i = *i + 1
		} else if fileType == ImgFSDirectory {
			*i = *i + 1
			if fileName != ".." {
				var err error
				contents[fileName], err = MountImgRecursive(ctx, msrc, metadata, fileMode, mmap, packageFD, i, length)
				if err != nil {
					return nil, fmt.Errorf("can't create recursive folder %v, err: %v", fileName, err)
				}
			} else {
				break
			}
		} else if fileType == ImgFSSymlink {
			link := metadata[*i].Link
			inode := newSymlink(ctx, msrc, link)
			contents[fileName] = inode
			*i = *i + 1
		} else if fileType == ImgFSWhiteoutFile {
			whitoutFiles = append(whitoutFiles, fileName)
			*i = *i + 1
		} else {
			return nil, fmt.Errorf("unknown file type %v (type: %v)", fileName, fileType)
		}
	}
	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(linux.FileMode(dirMode)))
	newinode := fs.NewInode(d, msrc, fs.StableAttr{
		DeviceID:  imgfsFileDevice.DeviceID(),
		InodeID:   imgfsFileDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Directory,
	})

	for _, fn := range whitoutFiles {
		newinode.InodeOperations.Setxattr(newinode, fs.XattrOverlayWhiteout(fn), []byte("y"))
	}
	return newinode, nil
}

func init() {
	fs.RegisterFilesystem(&Filesystem{})
}
