//go:build linux

package manager

import (
	"bytes"
	"sort"

	"github.com/relux-works/swarma-user-manager/internal/pc2store"
)

type censusNamedDirectory struct {
	Role     string                      `json:"role"`
	Name     string                      `json:"name"`
	Bindings []pc2store.DirectoryBinding `json:"bindings"`
}

type censusPhysicalIdentity struct {
	Role     string                `json:"role"`
	Name     string                `json:"name"`
	ID       string                `json:"storage_id"`
	Identity pc2store.FileIdentity `json:"identity"`
	Digest   string                `json:"digest"`
	Bytes    int64                 `json:"bytes"`
}

type censusCaptureEvidence struct {
	Fence       pc2store.FileIdentity    `json:"fence"`
	Directories []censusNamedDirectory   `json:"directories"`
	Heads       []censusPhysicalIdentity `json:"heads"`
	Physical    []censusPhysicalIdentity `json:"physical"`
}

var censusHeadRoles = [...]string{"root", "guard", "manager-inventory", "floor", "intent"}

// Copy the preauthenticated named relationships outside F. No FD survives in
// PreparedEvidence; these facts bind a snapshot, not a future authority lease.
func censusBindings(c *censusContext) ([]censusNamedDirectory, error) {
	if len(c.targets) != len(censusHeadRoles) {
		return nil, ErrCensusUnavailable
	}
	bindings := []censusNamedDirectory{}
	add := func(role, name string, directory *pc2store.ReadDirectory) error {
		chain, e := directory.Bindings()
		if e != nil {
			return e
		}
		bindings = append(bindings, censusNamedDirectory{role, name, chain})
		return nil
	}
	for i, target := range c.targets {
		if e := add(censusHeadRoles[i], target.Name, target.Directory); e != nil {
			return nil, e
		}
	}
	for _, item := range []struct {
		role string
		dir  *pc2store.ReadDirectory
	}{{"owner-index-root", c.pc2}, {"authority-fence-directory", c.fence}, {"native-effects", c.native["native-effects"]}, {"native-generations", c.native["native-generations"]}} {
		if e := add(item.role, "", item.dir); e != nil {
			return nil, e
		}
	}
	return bindings, nil
}

func sameCensusBindings(a, b []censusNamedDirectory) bool {
	left, e := canonical(a)
	right, other := canonical(b)
	return e == nil && other == nil && bytes.Equal(left, right)
}

func captureCensusEvidence(c *censusContext, bindings []censusNamedDirectory, heads []pc2store.FileImage, entries []pc2store.SnapshotEntry, native []nativeCensusImage) censusCaptureEvidence {
	vector := censusCaptureEvidence{c.fenceID, bindings, []censusPhysicalIdentity{}, []censusPhysicalIdentity{}}
	for i, image := range heads {
		vector.Heads = append(vector.Heads, censusPhysicalIdentity{
			Role: censusHeadRoles[i], Name: c.targets[i].Name, Identity: image.Identity,
			Digest: image.Digest, Bytes: image.Length(),
		})
	}
	for _, entry := range entries {
		vector.Physical = append(vector.Physical, censusPhysicalIdentity{
			Role: entry.Class, Name: entry.Location, ID: entry.ID, Identity: entry.Image.Identity,
			Digest: entry.Image.Digest, Bytes: entry.Image.Length(),
		})
	}
	for _, entry := range native {
		n := entry.observation
		vector.Physical = append(vector.Physical, censusPhysicalIdentity{
			Role: n.Role, Name: n.Directory + "/" + n.Name, ID: n.StorageID,
			Identity: entry.image.Identity, Digest: entry.image.Digest, Bytes: entry.image.Length(),
		})
	}
	sort.Slice(vector.Physical, func(i, j int) bool { return vector.Physical[i].ID < vector.Physical[j].ID })
	return vector
}
