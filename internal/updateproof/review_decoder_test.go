package updateproof

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"testing"
)

// Claim: the public verifier accepts an owned signed XZ fixture through the
// pinned native dpkg-deb descriptor and refuses a changed decoder pin with no
// evidence. This decodes only; it does not install a package or qualify a host.
func TestReviewNativeXZDecoder(t *testing.T) {
	f := newSignedFixture(t)
	members, err := arMembers(f.bundle.Archives["fixture:amd64"])
	if err != nil {
		t.Fatal(err)
	}
	var deb bytes.Buffer
	deb.WriteString("!<arch>\n")
	for _, name := range []string{"debian-binary", "control.tar.gz", "data.tar.gz"} {
		data := members[name]
		if name != "debian-binary" {
			gz, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(gz)
			if err != nil {
				t.Fatal(err)
			}
			if err = gz.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/usr/bin/xz", "--compress", "--stdout")
			cmd.Env = []string{}
			cmd.Stdin = bytes.NewReader(raw)
			data, err = cmd.Output()
			if err != nil {
				t.Fatal("fixture compression", err)
			}
			name = name[:len(name)-3] + ".xz"
		}
		fmt.Fprintf(&deb, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name+"/", 0, 0, 0, "100644", len(data))
		deb.Write(data)
		if len(data)%2 != 0 {
			deb.WriteByte('\n')
		}
	}
	f.rechain(deb.Bytes())
	f.profile.DPKGDeb = toolFixture(t, "/usr/bin/dpkg-deb")
	if _, err = Verify(context.Background(), f.profile, f.baseline, f.inv, f.bundle, f.clock); err != nil {
		t.Fatal("valid XZ signed chain", err)
	}
	f.profile.DPKGDeb.SHA256 = Digest([]byte("different qualified decoder"))
	evidence, err := Verify(context.Background(), f.profile, f.baseline, f.inv, f.bundle, f.clock)
	if err != ErrTool || !reflect.DeepEqual(evidence, Evidence{}) {
		t.Fatalf("decoder pin refusal: %v %+v", err, evidence)
	}
}
