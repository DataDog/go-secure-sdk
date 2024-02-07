package hashutil

import (
	"io/fs"
	"testing"
	"time"
)

var _ fs.FileInfo = (*fakeFileInfo)(nil)

type fakeFileInfo struct {
	isDir    bool
	modTime  time.Time
	fileMode fs.FileMode
	name     string
	size     int64
	sys      any
}

func (fk *fakeFileInfo) IsDir() bool        { return fk.isDir }
func (fk *fakeFileInfo) ModTime() time.Time { return fk.modTime }
func (fk *fakeFileInfo) Mode() fs.FileMode  { return fk.fileMode }
func (fk *fakeFileInfo) Name() string       { return fk.name }
func (fk *fakeFileInfo) Size() int64        { return fk.size }
func (fk *fakeFileInfo) Sys() any           { return fk.sys }

func Test_isAcceptableFileInfo(t *testing.T) {
	t.Parallel()

	type args struct {
		fi fs.FileInfo
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "directory",
			args: args{
				fi: &fakeFileInfo{
					isDir: true,
				},
			},
			wantErr: true,
		},
		{
			name: "symlink",
			args: args{
				fi: &fakeFileInfo{
					fileMode: fs.ModeSymlink,
				},
			},
			wantErr: true,
		},
		{
			name: "char device",
			args: args{
				fi: &fakeFileInfo{
					fileMode: fs.ModeCharDevice,
				},
			},
			wantErr: true,
		},
		{
			name: "device",
			args: args{
				fi: &fakeFileInfo{
					fileMode: fs.ModeDevice,
				},
			},
			wantErr: true,
		},
		{
			name: "named pipe",
			args: args{
				fi: &fakeFileInfo{
					fileMode: fs.ModeNamedPipe,
				},
			},
			wantErr: true,
		},
		{
			name: "socket",
			args: args{
				fi: &fakeFileInfo{
					fileMode: fs.ModeSocket,
				},
			},
			wantErr: true,
		},
		{
			name: "too large",
			args: args{
				fi: &fakeFileInfo{
					size: maxHashContent + 1,
				},
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				fi: &fakeFileInfo{
					isDir: false,
					size:  8,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := isAcceptableFileInfo(tt.args.fi); (err != nil) != tt.wantErr {
				t.Errorf("isAcceptableFileInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
