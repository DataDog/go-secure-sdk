package zip

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestCreate(t *testing.T) {
	t.Parallel()

	type args struct {
		fileSystem fs.FS
		opts       []Option
	}
	tests := []struct {
		name    string
		args    args
		wantW   []byte
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "path traversal attempt",
			args: args{
				fileSystem: &fstest.MapFS{
					"../../../bad": &fstest.MapFile{},
				},
			},
			wantErr: true,
		},
		{
			name: "file content too large",
			args: args{
				fileSystem: &fstest.MapFS{
					"big": &fstest.MapFile{
						Data: []byte("too-big-data"),
					},
				},
				opts: []Option{
					WithMaxFileSize(1),
				},
			},
			wantErr: true,
		},
		{
			name: "root is a file",
			args: args{
				fileSystem: &fstest.MapFS{
					".": &fstest.MapFile{},
				},
			},
			wantErr: true,
		},
		{
			name: "empty",
			args: args{
				fileSystem: &fstest.MapFS{},
			},
			wantErr: true,
		},
		{
			name: "invalid files",
			args: args{
				fileSystem: &fstest.MapFS{
					"dev/null": &fstest.MapFile{
						Mode: fs.ModeDevice,
					},
					"dev/stdin": &fstest.MapFile{
						Mode: fs.ModeCharDevice,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no inclusion matches",
			args: args{
				fileSystem: &fstest.MapFS{
					"test.txt": {
						Data: []byte(`Hello world !`),
					},
				},
				opts: []Option{
					WithIncludeFilter(func(path string, fi fs.FileInfo) bool {
						return false
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "exclude all",
			args: args{
				fileSystem: &fstest.MapFS{
					"test.txt": {
						Data: []byte(`Hello world !`),
					},
				},
				opts: []Option{
					WithExcludeFilter(func(path string, fi fs.FileInfo) bool {
						return true
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "header rewrite error",
			args: args{
				fileSystem: &fstest.MapFS{
					"test.txt": {
						Data: []byte(`Hello world !`),
					},
					"test2.txt": {
						Data: []byte(`Hello world !`),
					},
				},
				opts: []Option{
					WithHeaderRewritterFunc(func(hdr *zip.FileHeader) *zip.FileHeader {
						return nil
					}),
				},
			},
			wantErr: true,
		},
		// ---------------------------------------------------------------------
		{
			name: "sub-directory",
			args: args{
				fileSystem: &fstest.MapFS{
					"under":             {Mode: fs.ModeDir},
					"under/a":           {Mode: fs.ModeDir},
					"under/a/directory": {Mode: fs.ModeDir},
					"under/a/directory/test.txt": {
						Data: []byte(`deep content`),
					},
				},
			},
			wantErr: false,
			wantW: []byte{
				0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, //  |PK..........!...|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x74, 0x65, //  |..............te|
				0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x4a, 0x49, 0x4d, 0x2d, 0x50, 0x48, 0xce, 0xcf, 0x2b, 0x49, //  |st.txtJIM-PH..+I|
				0xcd, 0x2b, 0x01, 0x04, 0x00, 0x00, 0xff, 0xff, 0x50, 0x4b, 0x07, 0x08, 0x02, 0x2a, 0xb0, 0x2c, //  |.+......PK...*.,|
				0x12, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, //  |........PK......|
				0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x02, 0x2a, 0xb0, 0x2c, 0x12, 0x00, 0x00, 0x00, //  |......!..*.,....|
				0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, //  |................|
				0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x50, 0x4b, //  |......test.txtPK|
				0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x36, 0x00, 0x00, 0x00, 0x48, 0x00, //  |..........6...H.|
				0x00, 0x00, 0x00, 0x00, //                                                                          |....|
			},
		},
		{
			name: "sub-directory with empty directories",
			args: args{
				fileSystem: &fstest.MapFS{
					"under":             {Mode: fs.ModeDir},
					"under/a":           {Mode: fs.ModeDir},
					"under/a/directory": {Mode: fs.ModeDir},
					"under/a/directory/test.txt": {
						Data: []byte(`deep content`),
					},
				},
				opts: []Option{
					WithEmptyDirectories(true),
				},
			},
			wantErr: false,
			wantW: []byte{
				0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, //  |PK..........!...|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x75, 0x6e, //  |..............un|
				0x64, 0x65, 0x72, 0x2f, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |der/PK..........|
				0x21, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, //  |!...............|
				0x00, 0x00, 0x61, 0x2f, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |..a/PK..........|
				0x21, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, //  |!...............|
				0x00, 0x00, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x2f, 0x50, 0x4b, 0x03, 0x04, //  |..directory/PK..|
				0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |........!.......|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, //  |..........test.t|
				0x78, 0x74, 0x4a, 0x49, 0x4d, 0x2d, 0x50, 0x48, 0xce, 0xcf, 0x2b, 0x49, 0xcd, 0x2b, 0x01, 0x04, //  |xtJIM-PH..+I.+..|
				0x00, 0x00, 0xff, 0xff, 0x50, 0x4b, 0x07, 0x08, 0x02, 0x2a, 0xb0, 0x2c, 0x12, 0x00, 0x00, 0x00, //  |....PK...*.,....|
				0x0c, 0x00, 0x00, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, //  |....PK..........|
				0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |..!.............|
				0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x40, 0x00, 0x00, //  |.............@..|
				0x00, 0x00, 0x75, 0x6e, 0x64, 0x65, 0x72, 0x2f, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, //  |..under/PK......|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |......!.........|
				0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, //  |................|
				0x00, 0x40, 0x24, 0x00, 0x00, 0x00, 0x61, 0x2f, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, //  |.@$...a/PK......|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |......!.........|
				0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, //  |................|
				0x00, 0x40, 0x44, 0x00, 0x00, 0x00, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x2f, //  |.@D...directory/|
				0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21, 0x8a, //  |PK............!.|
				0x02, 0x2a, 0xb0, 0x2c, 0x12, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, //  |.*.,............|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x6c, 0x00, 0x00, 0x00, 0x74, 0x65, //  |..........l...te|
				0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, //  |st.txtPK........|
				0x04, 0x00, 0xd2, 0x00, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, //  |............|
			},
		},
		{
			name: "valid",
			args: args{
				fileSystem: &fstest.MapFS{
					"test.txt": {
						Data: []byte(`Hello world !`),
					},
				},
			},
			wantErr: false,
			wantW: []byte{
				0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, //  |PK..........!...|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x74, 0x65, //  |..............te|
				0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, //  |st.txt.H...W(./.|
				0x49, 0x51, 0x50, 0x04, 0x04, 0x00, 0x00, 0xff, 0xff, 0x50, 0x4b, 0x07, 0x08, 0x40, 0x2c, 0x0e, //  |IQP......PK..@,.|
				0x07, 0x13, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, //  |.........PK.....|
				0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x40, 0x2c, 0x0e, 0x07, 0x13, 0x00, 0x00, //  |.......!.@,.....|
				0x00, 0x0d, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //  |................|
				0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x50, //  |.......test.txtP|
				0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x36, 0x00, 0x00, 0x00, 0x49, //  |K..........6...I|
				0x00, 0x00, 0x00, 0x00, 0x00, //                                                                    |.....|
			},
		},
		{
			name: "valid with time reset",
			args: args{
				fileSystem: &fstest.MapFS{
					"test.txt": {
						ModTime: time.Now(),
						Data:    []byte(`Hello world !`),
					},
				},
				opts: []Option{
					WithHeaderRewritterFunc(ResetHeaderTimes()),
				},
			},
			wantErr: false,
			wantW: []byte{
				0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, //  |PK..........!...|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x74, 0x65, //  |..............te|
				0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, //  |st.txt.H...W(./.|
				0x49, 0x51, 0x50, 0x04, 0x04, 0x00, 0x00, 0xff, 0xff, 0x50, 0x4b, 0x07, 0x08, 0x40, 0x2c, 0x0e, //  |IQP......PK..@,.|
				0x07, 0x13, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, //  |.........PK.....|
				0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x40, 0x2c, 0x0e, 0x07, 0x13, 0x00, 0x00, //  |.......!.@,.....|
				0x00, 0x0d, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //  |................|
				0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x50, //  |.......test.txtP|
				0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x36, 0x00, 0x00, 0x00, 0x49, //  |K..........6...I|
				0x00, 0x00, 0x00, 0x00, 0x00, //                                                                    |.....|
			},
		},
		{
			name: "store only",
			args: args{
				fileSystem: &fstest.MapFS{
					"test.txt": {
						Data: []byte(`Hello world !`),
					},
				},
				opts: []Option{
					WithCompressFilter(func(path string, fi fs.FileInfo) bool {
						return false
					}),
				},
			},
			wantErr: false,
			wantW: []byte{
				0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x8a, 0x00, 0x00, //  |PK..........!...|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x74, 0x65, //  |..............te|
				0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, //  |st.txtHello worl|
				0x64, 0x20, 0x21, 0x50, 0x4b, 0x07, 0x08, 0x40, 0x2c, 0x0e, 0x07, 0x0d, 0x00, 0x00, 0x00, 0x0d, //  |d !PK..@,.......|
				0x00, 0x00, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, //  |...PK...........|
				0x00, 0x21, 0x8a, 0x40, 0x2c, 0x0e, 0x07, 0x0d, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x08, //  |.!.@,...........|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, //  |................|
				0x00, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, //  |.test.txtPK.....|
				0x00, 0x01, 0x00, 0x01, 0x00, 0x36, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, //        |.....6...C.....|
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := &bytes.Buffer{}
			if err := Create(tt.args.fileSystem, w, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if report := cmp.Diff(tt.wantW, w.Bytes()); report != "" {
				t.Errorf("Create() = \n%s", report)
			}
		})
	}
}
