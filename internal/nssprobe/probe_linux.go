//go:build linux && cgo

// Package nssprobe collects direct NSS module terminal statuses in a disposable
// subprocess. The parent enforces deadlines and authenticates the ELF closure.
// cgo is necessary for NSS's C structs and function-pointer ABI; os/user and
// getent do not expose the completion/error distinction required here.
package nssprobe

/*
#cgo LDFLAGS: -ldl
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <stdlib.h>
#include <string.h>

struct probe {
 void *handle; void *next; void *end; char *buffer;
 struct passwd pw; struct group gr; struct spwd sp;
};
static struct probe* begin(const char *path, int module, int kind) {
 struct probe *p = calloc(1, sizeof(*p)); if (!p) return NULL;
 p->handle = dlopen(path, RTLD_NOW|RTLD_LOCAL);
 if (!p->handle) { free(p); return NULL; }
 const char *sets[] = {"_nss_files_setpwent", "_nss_files_setgrent", "_nss_files_setspent"};
 const char *gets[] = {"_nss_files_getpwent_r", "_nss_files_getgrent_r", "_nss_files_getspent_r"};
 const char *ends[] = {"_nss_files_endpwent", "_nss_files_endgrent", "_nss_files_endspent"};
 const char *systemd_sets[] = {"_nss_systemd_setpwent", "_nss_systemd_setgrent", "_nss_systemd_setspent"};
 const char *systemd_gets[] = {"_nss_systemd_getpwent_r", "_nss_systemd_getgrent_r", "_nss_systemd_getspent_r"};
 const char *systemd_ends[] = {"_nss_systemd_endpwent", "_nss_systemd_endgrent", "_nss_systemd_endspent"};
 enum nss_status (*set)(int) = dlsym(p->handle, module ? systemd_sets[kind] : sets[kind]);
 p->next = dlsym(p->handle, module ? systemd_gets[kind] : gets[kind]); p->end = dlsym(p->handle, module ? systemd_ends[kind] : ends[kind]);
 p->buffer = calloc(1, 1048576);
 if (!set || !p->next || !p->end || !p->buffer || set(0)!=NSS_STATUS_SUCCESS) {
  if(p->buffer) free(p->buffer); dlclose(p->handle); free(p); return NULL;
 }
 return p;
}
static int next(struct probe *p, int kind) {
 int e=0; enum nss_status s;
 memset(p->buffer,0,1048576);
 if(kind==0) s=((enum nss_status(*)(struct passwd*,char*,size_t,int*))p->next)(&p->pw,p->buffer,1048576,&e);
 else if(kind==1) s=((enum nss_status(*)(struct group*,char*,size_t,int*))p->next)(&p->gr,p->buffer,1048576,&e);
 else s=((enum nss_status(*)(struct spwd*,char*,size_t,int*))p->next)(&p->sp,p->buffer,1048576,&e);
 // A clean terminal NOTFOUND is distinct from provider failure, TRYAGAIN or ERANGE.
 if(s==NSS_STATUS_SUCCESS) return 1;
 if(s==NSS_STATUS_NOTFOUND && (e==0 || e==ENOENT)) return 0;
 return -1;
}
static int finish(struct probe *p) {
 int ok=((enum nss_status(*)(void))p->end)()==NSS_STATUS_SUCCESS;
 explicit_bzero(p->buffer,1048576);free(p->buffer);
 ok=dlclose(p->handle)==0 && ok;free(p);return ok;
}
static char* member(struct probe *p,int i) { return p->gr.gr_mem ? p->gr.gr_mem[i] : NULL; }
static int locked(struct probe *p) { return p->sp.sp_pwdp && (p->sp.sp_pwdp[0]=='!' || p->sp.sp_pwdp[0]=='*'); }
*/
import "C"

import (
	"errors"
	"strconv"
	"strings"
	"unsafe"
)

// Snapshot has every database, even when empty. Secrets are converted to a lock
// boolean before leaving the C buffer; no password hash is emitted or retained.
type Snapshot struct {
	Passwd string `json:"passwd"`
	Group  string `json:"group"`
	Shadow string `json:"shadow"`
}

var errUnknown = errors.New("nss_probe_unknown")

func ReadFiles(path string, limit int) (Snapshot, error) { return readModule(path, 0, limit) }

// ReadFilesSystemd queries both reviewed ABIs rather than trusting glibc getent's
// exit code. Duplicate identical projections are coalesced, never conflicts.
func ReadFilesSystemd(files, systemd string, limit int) (Snapshot, error) {
	a, e := readModule(files, 0, limit)
	if e != nil {
		return Snapshot{}, e
	}
	b, e := readModule(systemd, 1, limit)
	if e != nil {
		return Snapshot{}, e
	}
	var out [3]string
	count, total := 0, 0
	for i, pair := range [][2]string{{a.Passwd, b.Passwd}, {a.Group, b.Group}, {a.Shadow, b.Shadow}} {
		seen := map[string]bool{}
		var rows strings.Builder
		for _, data := range pair {
			for _, line := range strings.Split(data, "\n") {
				if line == "" || seen[line] {
					continue
				}
				seen[line] = true
				count++
				total += len(line) + 1
				if count > limit || total > 8<<20 {
					return Snapshot{}, errUnknown
				}
				rows.WriteString(line)
				rows.WriteByte('\n')
			}
		}
		out[i] = rows.String()
	}
	return Snapshot{out[0], out[1], out[2]}, nil
}
func readModule(path string, module int, limit int) (Snapshot, error) {
	if limit < 1 || limit > 100000 {
		return Snapshot{}, errUnknown
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var tables [3]strings.Builder
	count := 0
	for kind := 0; kind < 3; kind++ {
		p := C.begin(cpath, C.int(module), C.int(kind))
		if p == nil {
			return Snapshot{}, errUnknown
		}
		bad := false
		for {
			status := C.next(p, C.int(kind))
			if status == 0 {
				break
			}
			if status != 1 {
				bad = true
				break
			}
			count++
			if count > limit {
				bad = true
				break
			}
			var fields []string
			switch kind {
			case 0:
				fields = []string{C.GoString(p.pw.pw_name), "x", strconv.FormatUint(uint64(p.pw.pw_uid), 10), strconv.FormatUint(uint64(p.pw.pw_gid), 10), "", C.GoString(p.pw.pw_dir), C.GoString(p.pw.pw_shell)}
			case 1:
				members := []string{}
				for i := 0; ; i++ {
					if i > limit {
						bad = true
						break
					}
					s := C.member(p, C.int(i))
					if s == nil {
						break
					}
					v := C.GoString(s)
					if strings.ContainsAny(v, ",:\x00\r\n") {
						bad = true
						break
					}
					members = append(members, v)
				}
				fields = []string{C.GoString(p.gr.gr_name), "x", strconv.FormatUint(uint64(p.gr.gr_gid), 10), strings.Join(members, ",")}
			case 2:
				lock := ""
				if C.locked(p) != 0 {
					lock = "!"
				}
				fields = []string{C.GoString(p.sp.sp_namp), lock, "", "", "", "", "", "", ""}
			}
			for _, v := range fields {
				if strings.ContainsAny(v, ":\x00\r\n") {
					bad = true
				}
			}
			if bad {
				break
			}
			tables[kind].WriteString(strings.Join(fields, ":") + "\n")
			if tables[0].Len()+tables[1].Len()+tables[2].Len() > 8<<20 {
				bad = true
				break
			}
		}
		if C.finish(p) == 0 {
			bad = true
		}
		if bad {
			return Snapshot{}, errUnknown
		}
	}
	return Snapshot{tables[0].String(), tables[1].String(), tables[2].String()}, nil
}
