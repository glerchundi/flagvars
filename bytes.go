package flagvars

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
)

// bytesHexValue adapts []byte for use as a flag. Value of flag is HEX encoded
type bytesHexValue []byte

// String implements flag.Value.String.
func (bytesHex bytesHexValue) String() string {
	return fmt.Sprintf("%X", []byte(bytesHex))
}

// Set implements flag.Value.Set.
func (bytesHex *bytesHexValue) Set(value string) error {
	data, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}

	*bytesHex = data

	return nil
}

// Type implements flag.Value.Type.
func (*bytesHexValue) Type() string {
	return "bytesHex"
}

// BytesHex creates and returns a new flag.Value compliant hex bytes parser.
func BytesHex(p *[]byte, value []byte) flag.Value {
	*p = value
	return (*bytesHexValue)(p)
}

// bytesBase64Value adapts []byte for use as a flag. Value of flag is Base64 encoded
type bytesBase64Value []byte

// String implements flag.Value.String.
func (bytesBase64 bytesBase64Value) String() string {
	return base64.StdEncoding.EncodeToString([]byte(bytesBase64))
}

// Set implements flag.Value.Set.
func (bytesBase64 *bytesBase64Value) Set(value string) error {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}

	*bytesBase64 = data

	return nil
}

// Type implements flag.Value.Type.
func (*bytesBase64Value) Type() string {
	return "bytesBase64"
}

// BytesBase64 creates and returns a new flag.Value compliant base64 bytes
// parser.
func BytesBase64(p *[]byte, value []byte) flag.Value {
	*p = value
	return (*bytesBase64Value)(p)
}

// bytesFileValue adapts []byte for use as a flag. Value of flag is the binary
// content of the specified file.
type bytesFileValue struct {
	filename string
	data     *[]byte
}

// String implements flag.Value.String.
func (bf bytesFileValue) String() string {
	return bf.filename
}

// Set implements flag.Value.Set.
func (bf *bytesFileValue) Set(value string) error {
	bf.filename = value

	data, err := ioutil.ReadFile(bf.filename)
	if err != nil {
		return err
	}

	*bf.data = data

	return nil
}

// Type implements flag.Value.Type.
func (*bytesFileValue) Type() string {
	return "bytesFile"
}

// BytesFile creates and returns a new flag.Value compliant base64 bytes parser.
func BytesFile(p *[]byte, value string) flag.Value {
	bf := &bytesFileValue{data: p}
	_ = bf.Set(value)
	return bf
}
