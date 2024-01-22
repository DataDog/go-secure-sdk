package atomic

import "io"

func ExampleWriteFile() {
	// Large and sensitive content to be written atomically
	var r io.Reader

	// The file will be created next to the destination, then the content will
	// wrtittent and finally if everything succeeded the target file will be
	// replaced.
	// Any error during the process will leave the existing file intact.
	if err := WriteFile("configuration.json", r); err != nil {
		panic(err)
	}
}
