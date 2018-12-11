package flagvars

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func setUpBytesHex(bytesHex *[]byte) *flag.FlagSet {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Var(BytesHex(bytesHex, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}), "bytes", "Some bytes in HEX")
	return f
}

func TestBytesHex(t *testing.T) {
	testCases := []struct {
		input    string
		success  bool
		expected string
	}{
		/// Positive cases
		{"", true, ""}, // Is empty string OK ?
		{"01", true, "01"},
		{"0101", true, "0101"},
		{"1234567890abcdef", true, "1234567890ABCDEF"},
		{"1234567890ABCDEF", true, "1234567890ABCDEF"},

		// Negative cases
		{"0", false, ""},   // Short string
		{"000", false, ""}, /// Odd-length string
		{"qq", false, ""},  /// non-hex character
	}

	devnull, _ := os.Open(os.DevNull)
	os.Stderr = devnull

	for i := range testCases {
		var bytesHex []byte
		f := setUpBytesHex(&bytesHex)

		tc := &testCases[i]

		// -bytes
		args := []string{
			fmt.Sprintf("-bytes=%s", tc.input),
		}

		err := f.Parse(args)
		if err != nil && tc.success == true {
			t.Errorf("expected success, got %q", err)
			continue
		} else if err == nil && tc.success == false {
			t.Errorf("expected failure while processing %q", tc.input)
			continue
		} else if tc.success {
			if fmt.Sprintf("%X", bytesHex) != tc.expected {
				t.Errorf("expected %q, got '%X'", tc.expected, bytesHex)
			}
		}
	}
}

func setUpBytesBase64(bytesBase64 *[]byte) *flag.FlagSet {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Var(BytesBase64(bytesBase64, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}), "bytes", "Some bytes in Base64")
	return f
}

func TestBytesBase64(t *testing.T) {
	testCases := []struct {
		input    string
		success  bool
		expected string
	}{
		/// Positive cases
		{"", true, ""}, // Is empty string OK ?
		{"AQ==", true, "AQ=="},

		// Negative cases
		{"AQ", false, ""}, // Padding removed
		{"ï", false, ""},  // non-base64 characters
	}

	devnull, _ := os.Open(os.DevNull)
	os.Stderr = devnull

	for i := range testCases {
		var bytesBase64 []byte
		f := setUpBytesBase64(&bytesBase64)

		tc := &testCases[i]

		// -bytes
		args := []string{
			fmt.Sprintf("-bytes=%s", tc.input),
		}

		err := f.Parse(args)
		if err != nil && tc.success == true {
			t.Errorf("expected success, got %q", err)
			continue
		} else if err == nil && tc.success == false {
			t.Errorf("expected failure while processing %q", tc.input)
			continue
		} else if tc.success {
			if base64.StdEncoding.EncodeToString(bytesBase64) != tc.expected {
				t.Errorf("expected %q, got '%X'", tc.expected, bytesBase64)
			}
		}
	}
}

func TestBytesFile(t *testing.T) {
	var bytesFile []byte
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Var(BytesFile(&bytesFile, ""), "bytes", "Some bytes from file")

	tf, err := ioutil.TempFile("", "")
	if err != nil {
		t.Errorf("expected success, got %q", err)
	}

	if _, err := tf.WriteString("teststring"); err != nil {
		t.Errorf("expected success, got %q", err)
	}

	if err := tf.Close(); err != nil {
		t.Errorf("expected success, got %q", err)
	}

	if err := f.Parse([]string{"-bytes=" + tf.Name()}); err != nil {
		t.Errorf("expected success, got %q", err)
	}

	fb, err := ioutil.ReadFile(tf.Name())
	if err != nil {
		t.Errorf("expected success, got %q", err)
	}

	if !bytes.Equal(bytesFile, fb) {
		t.Errorf("expected %q, got '%X'", bytesFile, fb)
	}
}
