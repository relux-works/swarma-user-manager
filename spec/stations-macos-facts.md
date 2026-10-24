# Read-only questions for macOS station qualification

This request collects facts for [the macOS backend draft](stations-macos-v0.md).
It authorizes no installation, account mutation, process stop, scheduler change,
root probe or qualification issuance. All commands below are PENDING-VERIFY
candidates on the requested version. The orchestrator relays this block to the
host lane; the spec producer does not contact that lane directly.

<!-- relay-block:start -->
Please collect F1–F8 on the proposed macOS 27.0.1 Apple-silicon host with SIP on,
as the existing ordinary user, without sudo or elevation. First report the
actual version/build/architecture; a mismatch is a fact, not a reason to change
the host. Run commands separately, preserving exact argv, stdout, stderr and
exit status. For a pipeline preserve both component statuses and pipefail.
Limit each query to 30 seconds and 256 KiB; report a timeout/truncation as
incomplete. Stop only the exact query PID you started if needed, never a shared
service. Do not grant privacy permissions, trigger developer-tool installation,
change settings or retry a denied command as root.

Do not return passwords, authentication attributes/blobs, tokens, Keychain
material, process arguments/environments or unrelated user file contents.
Do not query `Password`, `ShadowHashData` or `AuthenticationAuthority`, or read
backing directory database plists. Keep raw evidence private; redact personal
names, host IDs and directory endpoints consistently while preserving numeric
IDs, ordering, attribute names and error distinctions. No output here is host
qualification or permission to mutate anything.

F1. What OS/build, native architecture, current credentials and SIP state are
actually present? PENDING-VERIFY read-only probes:

```sh
/usr/bin/sw_vers
/usr/bin/uname -m
/usr/bin/uname -r
/usr/bin/id -u
/usr/bin/id -G
/usr/bin/csrutil status
```

F2. Which tools exist and which forms are documented by this exact build?
First use shell `command -v` for each name below. Read its local synopsis before
running the later query; if a flag/form is absent, report unsupported and skip
that query rather than guessing. Report tool path, synopsis and relevant flag
paragraphs, not a presumed version switch. PENDING-VERIFY commands:

```sh
command -v dscl dseditgroup dsmemberutil dscacheutil sysadminctl launchctl
command -v ls stat readlink getconf diskutil xattr ps ipcs crontab at
command -v otool dyld_info codesign sudo file lsof softwareupdate pkgutil spctl
MANPAGER=cat PAGER=cat /usr/bin/man sudo
MANPAGER=cat PAGER=cat /usr/bin/man dscl
MANPAGER=cat PAGER=cat /usr/bin/man dseditgroup
MANPAGER=cat PAGER=cat /usr/bin/man dsmemberutil
MANPAGER=cat PAGER=cat /usr/bin/man dscacheutil
MANPAGER=cat PAGER=cat /usr/bin/man launchctl
MANPAGER=cat PAGER=cat /usr/bin/man launchd.plist
MANPAGER=cat PAGER=cat /usr/bin/man xattr
MANPAGER=cat PAGER=cat /usr/bin/man getconf
MANPAGER=cat PAGER=cat /usr/bin/man crontab
MANPAGER=cat PAGER=cat /usr/bin/man at
/usr/sbin/sysadminctl -h
```

Return only bounded requested excerpts from manuals; record a bounded extract
as such, not the complete document. Help cannot prove creation/removal, disabled
login/token state, locking or partial-failure behavior; those stay root-fixture
questions. Do not invoke account create/delete, password or token-changing modes.

F3. What are the local/search nodes, policy order, UID/GID ranges and existing
non-human record shapes? `_www` is a candidate system account, not a required
host state: if absent, report that and suggest an existing non-human system
record without creating one. PENDING-VERIFY queries. Filters omit authentication fields; preserve pipeline
component statuses. The group-tool excerpt returns attribute headers only; the
explicit `dscl` selection supplies corresponding values.

```sh
set -o pipefail
/usr/bin/dscl localhost -list /
/usr/bin/dscl /Search -read / SearchPolicy CSPSearchPath LSPSearchPath NSPSearchPath
/usr/bin/dscl /Search/Contacts -read / SearchPolicy CSPSearchPath LSPSearchPath NSPSearchPath
/usr/bin/dscl . -read /Users/_www RecordName UniqueID PrimaryGroupID NFSHomeDirectory UserShell IsHidden GeneratedUID
/usr/bin/dscl /Local/Default -read /Users/_www RecordName UniqueID PrimaryGroupID NFSHomeDirectory UserShell IsHidden GeneratedUID
/usr/bin/dscl . -list /Users UniqueID
/usr/bin/dscl . -list /Groups PrimaryGroupID
/usr/bin/dscl /Local/Default -read /Groups/_www PrimaryGroupID GeneratedUID GroupMembership GroupMembers NestedGroups
/usr/sbin/dseditgroup -o read -n /Local/Default _www | /usr/bin/awk '/^[[:space:]]*dsAttrTypeStandard:(RecordName|PrimaryGroupID|GeneratedUID|GroupMembership|GroupMembers|NestedGroups)([[:space:]:=-]|$)/ {print}'
/usr/bin/dsmemberutil checkmembership -u _www -g admin
/usr/bin/id -G _www
/usr/bin/dscacheutil -q user -a name _www | /usr/bin/awk '/^(name|uid|gid|dir|shell):/ {print}'
/usr/bin/dscacheutil -q group -a name _www | /usr/bin/awk '/^(name|gid|users):/ {print}'
```

Preserve numeric ID collisions and missing-attribute versus missing-record,
permission, timeout and provider-error distinctions. Report observed minimum/
maximum IDs; no numeric range is thereby approved for stations. Identify
configured provider/node types without querying remote user data. Do not run
an unbounded search-node user enumeration. Local/cache views and one membership
check do not establish complete OpenDirectory or implicit-group behavior.

F4. Which launchd domain/job identity and result fields are visible without
root? We need structural excerpts only, no full job/environment dump. If the
following read-only forms are in the local manual, use an ordinary shell with
pipefail and record the `launchctl` status separately from the filter status.
PENDING-VERIFY probes; the filters retain only structural/status lines:

```sh
set -o pipefail
/bin/launchctl print system | /usr/bin/awk 'NR==1 || /^[[:space:]]*(type|state|active count) =/'
/bin/launchctl print system/com.apple.opendirectoryd | /usr/bin/awk 'NR==1 || /^[[:space:]]*(type|state|pid|runs|last exit code|domain) =/'
/bin/launchctl print "user/$(/usr/bin/id -u)" | /usr/bin/awk 'NR==1 || /^[[:space:]]*(type|state|active count) =/'
/bin/launchctl print "gui/$(/usr/bin/id -u)" | /usr/bin/awk 'NR==1 || /^[[:space:]]*(type|state|active count) =/'
```

Report missing/denied domains exactly. From local manual excerpts, identify
read-only fields concerning instance identity, process start, latest invocation,
exit/result and queued triggers. Do not run bootstrap, bootout, kickstart,
kill, enable or disable. These snippets cannot establish root-issuer binding
or the absence of other jobs.

F5. What are APFS/ownership/alias and metadata facts, and the collecting user's
own OS-assigned temp/cache paths? Directory-only metadata and attribute NAMES
are sufficient; do not list private contents or dump xattr values.
PENDING-VERIFY queries:

```sh
/usr/sbin/diskutil info /
/usr/sbin/diskutil info /System/Volumes/Data
/bin/ls -ldeO@ / /Library /opt /System/Volumes/Data /private /private/tmp /private/var /private/var/tmp /private/var/folders /private/var/run
/bin/ls -ldeO@ /tmp /var /var/folders /var/run /Library/LaunchAgents /Library/LaunchDaemons /System/Library/LaunchAgents /System/Library/LaunchDaemons
/usr/bin/readlink /tmp
/usr/bin/readlink /var
/usr/bin/readlink /var/run
/usr/bin/getconf DARWIN_USER_TEMP_DIR
/usr/bin/getconf DARWIN_USER_CACHE_DIR
/usr/bin/xattr /Library
/usr/bin/xattr /private/var/folders
```

For each exact own-user temp/cache path returned by getconf, first inspect it
as a literal path, then run `/bin/ls -ldeO@ 'LITERAL_PATH'` and
`/usr/bin/stat -f '%u %g %Sp %Sf %N' 'LITERAL_PATH'`, substituting only that
reviewed path, never evaluating output as shell code. No recursion/globbing
into other users' trees. Report volume type, ownership-enabled/case semantics,
ACL presence, BSD flags, attribute names, aliases and permission errors. This
cannot prove future station temp mappings or durable publication semantics.

F6. Which process, scheduler, runtime and IPC observation surfaces are visible?
PENDING-VERIFY read-only probes; metadata only, no jobs submitted or processes
signalled, and no user crontab contents requested:

```sh
/bin/ps -axo pid=,ppid=,ruid=,uid=,gid=,stat=
/usr/bin/ipcs -a
/bin/ls -ldeO@ /usr/lib/cron /usr/lib/cron/tabs /usr/lib/cron/jobs /usr/lib/cron/spool /usr/lib/cron/cron.allow /usr/lib/cron/cron.deny /usr/lib/cron/at.allow /usr/lib/cron/at.deny /etc/crontab
```

Also return local manual synopsis/excerpts for `ps`, `ipcs`, `lsof`, `shm_open`,
`sem_open`, `proc_pidinfo`, `flock` and `fsync` if available, using the same
`MANPAGER=cat PAGER=cat /usr/bin/man NAME` form. Distinguish unknown/missing
interfaces from proven absent resource classes. Do not read IPC data or probe
other users' sockets. These observations cannot prove complete saved-UID,
holder, Mach-right, process-absence or persistence-denial coverage.

F7. Which native code, dyld/cache and signature introspection tools are already
installed? Only if F2 confirms the existing executable and synopsis, collect
PENDING-VERIFY read-only output:

```sh
/usr/bin/file /usr/bin/dscl /usr/sbin/dseditgroup /usr/sbin/sysadminctl /bin/launchctl
/usr/bin/otool -L /usr/bin/dscl
/usr/bin/codesign -d --verbose=2 /usr/bin/dscl
/bin/ls -ld /System/Library/dyld /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld
```

Report whether the local `dyld_info` manual exposes read-only dependency/cache
identity forms; no guessed flags, cache extraction, developer-tool download,
`xcrun` installer prompt, injected library or target process launch. A missing
standalone dylib/cache path is not proof that an image is unavailable. Complete
loaded-image closure still requires a separately reviewed native/root test.

F8. Which authenticity and installed-update reporting surfaces exist on this
build? PENDING-VERIFY read-only queries, after local synopsis confirmation:

```sh
MANPAGER=cat PAGER=cat /usr/bin/man softwareupdate
MANPAGER=cat PAGER=cat /usr/bin/man pkgutil
MANPAGER=cat PAGER=cat /usr/bin/man codesign
MANPAGER=cat PAGER=cat /usr/bin/man spctl
/usr/sbin/softwareupdate --history
```

Return bounded synopsis/verification-field excerpts and local history only;
redact unrelated package/personal metadata. No update list/download/install,
package execution, security-policy change or requalification is requested.
Receipts/history alone cannot prove an authentic update, the active signed
system seal/Cryptex state or safe automatic pin authority. State which required
trust/installed-state evidence remains unavailable without a later reviewed
native/root qualification procedure; do not attempt it on this facts host.

Please return each question's evidence, unsupported/denied queries and remaining
visibility limits. Read-only success verifies only the exact observation; all
mutation, stop, absence, journal durability, issuer authentication and isolation
claims stay PENDING-VERIFY. No public posting of raw machine evidence is asked.
<!-- relay-block:end -->
