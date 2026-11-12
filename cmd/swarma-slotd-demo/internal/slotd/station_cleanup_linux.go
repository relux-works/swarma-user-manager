//go:build linux

package slotd

import (
	"errors"
	"os"
	"path"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
	"golang.org/x/sys/unix"
)

type custodyDeletion struct {
	spec     stationSpec
	relative string
	identity custodyReceipt
}

// This typed plan never broadens the home walker. Every immutable object needs
// its creation receipt; only the journal's own bounded regular turns/temporaries
// may lack one. All trees are planned before any unlink or account retirement.
func stationDeletionPlan(roots stationRoots, r *durableRecord) ([]custodyDeletion, error) {
	if r.Station == nil {
		return nil, errStationCustody
	}
	var out []custodyDeletion
	for _, s := range stationSpecs {
		flags := unix.O_RDONLY | unix.O_NONBLOCK
		if s.directory {
			flags |= unix.O_DIRECTORY
		}
		f, err := openBelow(stationRoot(roots, s), stationRelative(r.Identity.UID, s), flags)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		want, ok := r.Station.object(s.name)
		if !ok {
			f.Close()
			return nil, errStationCustody
		}
		// Corrupt contents and zero lengths are removable; inode, ownership,
		// type, mode, links, ACL and mount custody remain mandatory.
		var se error
		if s.directory {
			se = checkStationObject(f, s, r.Identity.UID, want)
		} else {
			se = checkStationDeletionFile(f, s, r.Identity.UID, want)
		}
		if se != nil {
			f.Close()
			return nil, se
		}
		if s.directory {
			names, e := freshNames(f, 10002)
			if e != nil {
				f.Close()
				return nil, e
			}
			for _, name := range names {
				if s.name == "journal" {
					if name == "binding.json" || name == "delivery.lock" {
						continue
					}
					if !journalEntryName(name) {
						f.Close()
						return nil, errStationCustody
					}
					child, e := childFD(f, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
					if e != nil {
						f.Close()
						return nil, e
					}
					identity, e := directoryIdentity(child)
					entry := stationSpec{name: "turn", relative: "journal/" + name, slotOwner: true, mode: 0600, max: 16 << 20}
					if e == nil {
						e = checkStationDeletionFile(child, entry, r.Identity.UID, identity)
					}
					child.Close()
					if e != nil {
						f.Close()
						return nil, e
					}
					out = append(out, custodyDeletion{entry, stationRelative(r.Identity.UID, entry), custodyReceipt{Name: entry.name, Directory: identity}})
					continue
				}
				found := false
				for _, childSpec := range stationSpecs {
					if childSpec.anchor == s.anchor && path.Dir(childSpec.relative) == s.relative && childSpec.relative != "." && path.Base(childSpec.relative) == name {
						found = true
						break
					}
					if s.relative == "." && childSpec.anchor == s.anchor && childSpec.relative != "." && path.Dir(childSpec.relative) == "." && path.Base(childSpec.relative) == name {
						found = true
						break
					}
				}
				if !found {
					f.Close()
					return nil, errStationCustody
				}
			}
		}
		f.Close()
		out = append(out, custodyDeletion{s, stationRelative(r.Identity.UID, s), custodyReceipt{Name: s.name, Directory: want}})
	}
	return out, nil
}

func checkStationDeletionFile(f *os.File, s stationSpec, uid uint32, wantDirectory payloadlaunch.Directory) error {
	// Delegating the metadata contract with an independent size check avoids
	// reading damaged or secret bytes merely to delete an owned regular file.
	st, err := fdStat(f)
	if err != nil {
		return err
	}
	owner, gid := uint32(0), uid
	if s.slotOwner {
		owner = uid
	}
	if s.anchor {
		gid = 0
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != s.mode || st.Uid != owner || st.Gid != gid || st.Nlink != 1 || st.Size < 0 || (s.name == "turn" && st.Size > 16<<20) {
		return errStationCustody
	}
	actual, err := directoryIdentity(f)
	if err != nil {
		return err
	}
	if actual != wantDirectory {
		return errStationCustody
	}
	return noACL(f)
}

func removeStation(roots stationRoots, r *durableRecord) error {
	plan, err := stationDeletionPlan(roots, r)
	if err != nil {
		return err
	}
	// Leaves precede their containing directories regardless of which role was
	// enumerated first. Anchor publication is retired before envelope contents.
	for len(plan) > 0 {
		best := 0
		for i := range plan {
			if plan[i].spec.anchor && !plan[best].spec.anchor || plan[i].spec.anchor == plan[best].spec.anchor && len(plan[i].relative) > len(plan[best].relative) {
				best = i
			}
		}
		entry := plan[best]
		plan = append(plan[:best], plan[best+1:]...)
		root := stationRoot(roots, entry.spec)
		f, e := openBelow(root, entry.relative, unix.O_RDONLY|unix.O_NONBLOCK)
		if e != nil {
			return e
		}
		if entry.spec.directory {
			e = checkStationObject(f, entry.spec, r.Identity.UID, entry.identity.Directory)
		} else {
			e = checkStationDeletionFile(f, entry.spec, r.Identity.UID, entry.identity.Directory)
		}
		f.Close()
		if e != nil {
			return e
		}
		parent, e := openBelow(root, path.Dir(entry.relative), unix.O_RDONLY|unix.O_DIRECTORY)
		if e != nil {
			return e
		}
		flags := 0
		if entry.spec.directory {
			flags = unix.AT_REMOVEDIR
		}
		e = unix.Unlinkat(int(parent.Fd()), path.Base(entry.relative), flags)
		if e == nil {
			e = parent.Sync()
		}
		parent.Close()
		if e != nil {
			return e
		}
	}
	// Tombstone/reuse requires both top-level namespaces absent, not a partial
	// success inferred from deletion counts or a missing account.
	return absentStation(roots, r.Identity.UID)
}
