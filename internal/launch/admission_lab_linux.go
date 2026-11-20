//go:build linux && manager_lab

package launch

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

type labSurface struct {
	Format   string            `json:"format"`
	Fields   map[string]string `json:"fields"`
	MaxBytes int               `json:"max_bytes"`
}

type labInventory struct {
	Structures map[string]struct {
		Fields map[string]string `json:"fields"`
	} `json:"structures"`
	Surfaces []labSurface `json:"surfaces"`
}

var labInventoryValue = func() labInventory {
	var inventory labInventory
	if json.Unmarshal([]byte(labAdmissionInventory), &inventory) != nil {
		panic("invalid compiled lab inventory")
	}
	return inventory
}()

var labUSDPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})\.[0-9]{6}$`)
var labCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var labOperationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func labUSD(value string) (int64, bool) {
	if !labUSDPattern.MatchString(value) {
		return 0, false
	}
	amount, err := strconv.ParseInt(strings.ReplaceAll(value, ".", ""), 10, 64)
	return amount, err == nil && amount > 0 && amount <= labObservationMaxSequence
}

func labCanonical(raw []byte, limit int) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, fail("lab_start_invalid")
	}
	parsed, err := ccj.Parse(raw, ccj.RegistrationMalformed)
	if err != nil {
		return nil, fail("lab_start_invalid")
	}
	canonical, err := ccj.Marshal(parsed, ccj.RegistrationMalformed)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, fail("lab_start_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if decoder.Decode(&object) != nil || object == nil {
		return nil, fail("lab_start_invalid")
	}
	return object, nil
}

func labShapeObject(value any, fields map[string]string) bool {
	object, ok := value.(map[string]any)
	if !ok || fields == nil || len(object) != len(fields) {
		return false
	}
	for name, grammar := range fields {
		member, found := object[name]
		if !found || member == nil || !labShapeValue(member, grammar) {
			return false
		}
	}
	return true
}

func labShapeValue(value any, grammar string) bool {
	if strings.HasPrefix(grammar, "[]") {
		members, ok := value.([]any)
		if !ok || len(members) > 256 {
			return false
		}
		for _, member := range members {
			if !labShapeValue(member, grammar[2:]) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(grammar, "@") {
		return labShapeObject(value, labInventoryValue.Structures[grammar[1:]].Fields)
	}
	if grammar == "bool" {
		_, ok := value.(bool)
		return ok
	}
	switch grammar {
	case "uint", "positive", "root", "invocation-count", "output-tokens", "wall-ms":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		integer, err := number.Int64()
		if err != nil || integer < 0 || integer > labObservationMaxSequence {
			return false
		}
		switch grammar {
		case "uint":
			return true
		case "root":
			return integer == 0
		case "invocation-count":
			return integer >= 1 && integer <= 256
		case "output-tokens":
			return integer >= 1 && integer <= 128000
		case "wall-ms":
			return integer >= 1 && integer <= 900000
		default:
			return integer > 0
		}
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	switch {
	case strings.HasPrefix(grammar, "="):
		return text == grammar[1:]
	case strings.Contains(grammar, "|"):
		for _, option := range strings.Split(grammar, "|") {
			if text == option {
				return true
			}
		}
		return false
	}
	switch grammar {
	case "id":
		if len(text) < 1 || len(text) > 128 {
			return false
		}
		for _, character := range []byte(text) {
			if character < 0x21 || character > 0x7e {
				return false
			}
		}
		return true
	case "native-id":
		return manager.ValidRequestID(text)
	case "operation":
		return labOperationPattern.MatchString(text)
	case "uuid":
		return bootPattern.MatchString(text)
	case "commit":
		return labCommitPattern.MatchString(text)
	case "digest":
		return strings.HasPrefix(text, "sha256:") && len(text) == 71 && manager.HashOK(text[7:])
	case "usd":
		_, valid := labUSD(text)
		return valid
	case "time":
		instant, err := time.Parse(time.RFC3339Nano, text)
		return err == nil && instant.After(time.Unix(0, 0)) && instant.UTC().Format(time.RFC3339Nano) == text
	}
	return false
}

func labRecord(raw []byte, format string) (map[string]any, error) {
	for _, surface := range labInventoryValue.Surfaces {
		if surface.Format != format {
			continue
		}
		object, err := labCanonical(raw, surface.MaxBytes)
		if err != nil || !labShapeObject(object, surface.Fields) {
			return nil, fail("lab_start_invalid")
		}
		return object, nil
	}
	return nil, fail("lab_start_invalid")
}

func labMap(object map[string]any, name string) map[string]any {
	value, _ := object[name].(map[string]any)
	return value
}
func labString(object map[string]any, name string) string {
	value, _ := object[name].(string)
	return value
}
func labInteger(object map[string]any, name string) int64 {
	value, _ := object[name].(json.Number)
	integer, _ := value.Int64()
	return integer
}
func labTrue(object map[string]any, name string) bool { value, _ := object[name].(bool); return value }
func labObjectDigest(value any) string {
	raw, err := manager.ObjectBytes(value)
	if err != nil {
		return ""
	}
	return labDigest(raw)
}

func labPinnedBytes(raw []byte, expected string) bool {
	return labShapeValue(expected, "digest") && labDigest(raw) == expected
}

func labTarget(object map[string]any, omit, domain string) string {
	image := map[string]any{}
	for name, value := range object {
		if name != omit {
			image[name] = value
		}
	}
	return labObjectDigest(map[string]any{"domain": domain, "record": image})
}

func labApproval(record map[string]any, member string, now time.Time) bool {
	approval := labMap(record, member)
	approved, err := time.Parse(time.RFC3339Nano, labString(approval, "approved_at"))
	if err != nil || now.Before(approved) {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, labString(approval, "expires_at"))
	return err == nil && now.Before(expires) && labString(approval, "approved_sha256") == labTarget(record, member, "swarma-broker-lab-approval-target/1")
}

type labStartBinding struct {
	Format           string `json:"format"`
	RequestID        string `json:"request_id"`
	StartID          string `json:"start_id"`
	Generation       string `json:"generation"`
	Epoch            int64  `json:"epoch"`
	PlanSHA256       string `json:"plan_sha256"`
	InvocationSHA256 string `json:"invocation_sha256"`
	ApprovalSHA256   string `json:"approval_sha256"`
	ReleaseSHA256    string `json:"release_sha256"`
	AccessSHA256     string `json:"access_sha256"`
	GroupSHA256      string `json:"group_sha256"`
	PriceSHA256      string `json:"price_sha256"`
	ContextSHA256    string `json:"context_sha256"`
	HeadsSHA256      string `json:"heads_sha256"`
	BootID           string `json:"boot_id"`
	QualifiedAt      string `json:"qualified_at"`
	QualifiedMS      int64  `json:"qualified_monotonic_ms"`
	ExpiresMS        int64  `json:"expires_monotonic_ms"`
	AvailableCap     int64  `json:"available_cap_micro_usd"`
	StoreGeneration  string `json:"store_generation"`
	Revoked          bool   `json:"revoked"`
}

type labStartCheck func(string, int64) bool

func (launcher Launcher) admitLabStart(request Request, mapping *launchMapping, executor approvedExecutor, boot string, now int64, nativeHead genjournal.Floor) (labStartCheck, error) {
	if mapping == nil || !labMappingValid(*mapping) {
		var status unix.Stat_t
		if err := unix.Fstatat(int(launcher.Store.dir.Fd()), "lab-observation-store.json", &status, unix.AT_SYMLINK_NOFOLLOW); err == unix.ENOENT {
			return nil, nil
		}
		return nil, fail("lab_start_unapproved")
	}
	read := func(name string, limit int) ([]byte, error) {
		return manager.ReadProtected(launcher.Store.dir, name, launcher.Store.owner, limit)
	}
	raw, err := read("lab-start-admission", 65536)
	var binding labStartBinding
	if err != nil || manager.Strict(raw, &binding) != nil || binding.Format != "station-lab-start-admission/1" {
		return nil, fail("lab_start_unapproved")
	}
	if binding.Revoked {
		return nil, fail("lab_start_unapproved")
	}
	storeGeneration, err := launcher.Store.labStoreGeneration()
	if err != nil || storeGeneration != binding.StoreGeneration {
		return nil, fail("lab_start_unapproved")
	}
	if binding.RequestID != request.ID || binding.StartID != request.ExecutionID || binding.Generation != request.Generation || binding.Epoch != request.Epoch || binding.PlanSHA256 != labDigest(request.Plan) || binding.BootID != boot || binding.QualifiedMS < 0 || now < binding.QualifiedMS || binding.ExpiresMS <= now || binding.ExpiresMS > labObservationMaxSequence || binding.AvailableCap <= 0 || binding.AvailableCap > labObservationMaxSequence {
		return nil, fail("lab_start_unapproved")
	}
	qualified, err := time.Parse(time.RFC3339Nano, binding.QualifiedAt)
	if err != nil || qualified.UTC().Format(time.RFC3339Nano) != binding.QualifiedAt || !qualified.After(time.Unix(0, 0)) {
		return nil, fail("lab_start_unapproved")
	}
	if now-binding.QualifiedMS > 900000 || binding.ExpiresMS-binding.QualifiedMS > 900000 {
		return nil, fail("lab_start_unapproved")
	}
	records := map[string]map[string]any{}
	for _, entry := range []struct {
		name, format, digest string
		limit                int
	}{
		{"invocation", "swarma-broker-lab-bounded-invocation/1", binding.InvocationSHA256, 65536},
		{"approval", "swarma-broker-lab-off-vm-approval/1", binding.ApprovalSHA256, 65536},
		{"release", "swarma-lab-release-set/1", binding.ReleaseSHA256, 262144},
		{"access", "swarma-broker-lab-access-attestation/1", binding.AccessSHA256, 65536},
		{"group", "swarma-broker-lab-attempt-group/1", binding.GroupSHA256, 65536},
		{"price", "swarma-broker-lab-model-price/1", binding.PriceSHA256, 65536},
	} {
		data, readErr := read("lab-"+entry.name, entry.limit)
		if readErr != nil || !labPinnedBytes(data, entry.digest) {
			return nil, fail("lab_start_unapproved")
		}
		record, shapeErr := labRecord(data, entry.format)
		if shapeErr != nil {
			return nil, shapeErr
		}
		records[entry.name] = record
	}
	plan, err := labRecord(request.Plan, "swarma-broker-lab-launch-plan/1")
	if err != nil {
		return nil, err
	}
	head := labMap(labMap(plan, "predecessor_heads"), "manager")
	if labInteger(head, "sequence") != nativeHead.Seq || labString(head, "sha256") != "sha256:"+nativeHead.Hash {
		return nil, fail("lab_start_unapproved")
	}
	if !launcher.labNativeManagerJoin(plan, request.Generation, nativeHead) {
		return nil, fail("lab_start_unapproved")
	}
	for _, entry := range []struct{ name, digest string }{{"client", labString(records["invocation"], "client_profile_sha256")}, {"wire", labString(records["invocation"], "wire_profile_sha256")}} {
		data, readErr := read("lab-"+entry.name, 262144)
		if readErr != nil || !labPinnedBytes(data, entry.digest) {
			return nil, fail("lab_start_unapproved")
		}
	}
	currentBoot, currentMS, clockErr := launcher.Clock.Now()
	if clockErr != nil || currentBoot != boot || currentMS < now || currentMS >= binding.ExpiresMS || currentMS-binding.QualifiedMS > 900000 {
		return nil, fail("lab_start_unapproved")
	}
	now = currentMS
	instant := qualified.Add(time.Duration(now-binding.QualifiedMS) * time.Millisecond)
	deadline, err := labApprovedStart(binding, records, plan, executor, boot, now, instant)
	if err != nil {
		return nil, err
	}
	return func(currentBoot string, currentMS int64) bool {
		if currentBoot != boot || currentMS < now || currentMS >= deadline {
			return false
		}
		now = currentMS
		return true
	}, nil
}

func labApprovedStart(binding labStartBinding, records map[string]map[string]any, launch map[string]any, executor approvedExecutor, boot string, now int64, instant time.Time) (int64, error) {
	deny := func() (int64, error) { return 0, fail("lab_start_unapproved") }
	plan, approval, release := records["invocation"], records["approval"], records["release"]
	access, group, price := records["access"], records["group"], records["price"]
	if labString(release, "contract_index_sha256") != "sha256:93c3301da1eab5ff2c3a54af4903c95952f4f69f44f8b55a8707fa655b449925" || binding.PriceSHA256 != "sha256:ab24597d9db7e908b1127efcabe049637e8e70eea61b1ee318528b7e5bcaeebf" {
		return deny()
	}
	if !labTrue(plan, "live_budget_approved") || labString(plan, "approval_record_sha256") != binding.ApprovalSHA256 || labString(plan, "executor_sha256") != "sha256:"+executor.Digest || labString(plan, "target_generation") != binding.Generation {
		return deny()
	}
	if labString(plan, "client_profile_sha256") != "sha256:69f8e2369cd279d5a13d5629a65324b6ea63d7f71f35475035373bd3f3318e22" || labString(plan, "wire_profile_sha256") != "sha256:6b0196268f5e920abf0cdfe10b2f94fb6ebccbb9dc330d3f218217b01f91423f" || labString(plan, "model") != "claude-opus-5-5" || labInteger(plan, "max_output_tokens_per_invocation") != 128000 {
		return deny()
	}
	if labInteger(plan, "max_wall_time_per_invocation_ms") > labInteger(plan, "max_wall_time_total_ms") {
		return deny()
	}
	amount, valid := labUSD(labString(plan, "max_total_cost_usd"))
	if !valid || amount > binding.AvailableCap {
		return deny()
	}
	context := labMap(plan, "context")
	if labObjectDigest(context) != binding.ContextSHA256 {
		return deny()
	}
	for _, record := range []map[string]any{approval, release, access, group, launch} {
		if !reflect.DeepEqual(context, labMap(record, "context")) {
			return deny()
		}
	}
	qualification, _ := time.Parse(time.RFC3339Nano, labString(context, "qualification_expires_at"))
	if !instant.Before(qualification) {
		return deny()
	}
	for _, entry := range []struct {
		record map[string]any
		member string
	}{{approval, "approval"}, {release, "owner_approval"}, {access, "owner_approval"}} {
		if !labApproval(entry.record, entry.member, instant) {
			return deny()
		}
	}
	offVM, _ := time.Parse(time.RFC3339Nano, labString(approval, "off_vm_now"))
	approved, _ := time.Parse(time.RFC3339Nano, labString(labMap(approval, "approval"), "approved_at"))
	if offVM.Before(approved) || instant.Before(offVM) {
		return deny()
	}
	target := labTarget(plan, "approval_record_sha256", "swarma-broker-lab-bounded-invocation-target/1")
	if labString(approval, "invocation_sha256") != target || labString(release, "invocation_sha256") != target || labString(approval, "release_set_sha256") != binding.ReleaseSHA256 || labString(approval, "access_attestation_sha256") != binding.AccessSHA256 {
		return deny()
	}
	if !reflect.DeepEqual(launch["predecessor_heads"], approval["heads"]) || labObjectDigest(approval["heads"]) != binding.HeadsSHA256 {
		return deny()
	}
	if labString(launch, "operation_id") != labString(plan, "operation_id") || labString(launch, "target_generation") != binding.Generation {
		return deny()
	}
	pins := labMap(launch, "pins")
	for name, expected := range map[string]string{"invocation_sha256": target, "off_vm_approval_sha256": binding.ApprovalSHA256, "release_set_sha256": binding.ReleaseSHA256, "access_attestation_sha256": binding.AccessSHA256} {
		if labString(pins, name) != expected {
			return deny()
		}
	}
	seen := map[string]string{}
	for _, value := range launch["input_pins"].([]any) {
		pin := value.(map[string]any)
		name := labString(pin, "name")
		if _, duplicate := seen[name]; duplicate {
			return deny()
		}
		seen[name] = labString(pin, "sha256")
	}
	for name, expected := range map[string]string{"bounded-invocation": binding.InvocationSHA256, "client-profile": labString(plan, "client_profile_sha256"), "wire-profile": labString(plan, "wire_profile_sha256"), "bounded-executor": labString(plan, "executor_sha256")} {
		if seen[name] != expected {
			return deny()
		}
	}
	for name, expected := range map[string]string{"plan_sha256": binding.InvocationSHA256, "approval_record_sha256": binding.ApprovalSHA256, "release_set_sha256": binding.ReleaseSHA256, "launch_plan_sha256": binding.PlanSHA256, "model_price_sha256": binding.PriceSHA256, "operation_id": labString(plan, "operation_id"), "start_operation_id": binding.RequestID, "start_id": binding.StartID, "boot_id": boot} {
		if labString(group, name) != expected {
			return deny()
		}
	}
	started := labInteger(group, "group_started_monotonic_ms")
	total := labInteger(plan, "max_wall_time_total_ms")
	if started > now || now-started >= total || started > labObservationMaxSequence-total {
		return deny()
	}
	deadline := started + total
	if binding.ExpiresMS < deadline {
		deadline = binding.ExpiresMS
	}
	for _, expiry := range []time.Time{qualification, offVMApprovalExpiry(approval, "approval"), offVMApprovalExpiry(release, "owner_approval"), offVMApprovalExpiry(access, "owner_approval"), offVMApprovalExpiry(access, "")} {
		remaining := expiry.Sub(instant) / time.Millisecond
		if remaining <= 0 {
			return deny()
		}
		if int64(remaining) < deadline-now {
			deadline = now + int64(remaining)
		}
	}
	if !labAccessSafe(access, instant) || labString(price, "model") != labString(plan, "model") || labInteger(price, "output_token_ceiling") < labInteger(plan, "max_output_tokens_per_invocation") {
		return deny()
	}
	priceMembers := 0
	for _, value := range release["assets"].([]any) {
		asset := value.(map[string]any)
		if !labTrue(asset, "second_build_equal") || labString(asset, "sha256") != labString(asset, "second_build_sha256") {
			return deny()
		}
		for _, memberValue := range asset["members"].([]any) {
			member := memberValue.(map[string]any)
			if labString(asset, "product") == "gateway" && labString(member, "path") == "contracts/lab-v0/model-price.json" {
				priceMembers++
				if labString(member, "mode") != "0644" || labString(member, "sha256") != binding.PriceSHA256 {
					return deny()
				}
			}
		}
	}
	if priceMembers != 1 {
		return deny()
	}
	return deadline, nil
}

func (launcher Launcher) labNativeManagerJoin(plan map[string]any, generation string, head genjournal.Floor) bool {
	join := labMap(plan, "manager_join")
	receipt := labMap(join, "receipt")
	if labString(join, "request_id") != labString(receipt, "request_id") || labString(join, "request_sha256") != labString(receipt, "request_sha256") || labString(receipt, "result") != "committed" || labInteger(labMap(receipt, "journal_head"), "sequence") != head.Seq || labString(labMap(receipt, "journal_head"), "sha256") != "sha256:"+head.Hash {
		return false
	}
	raw, err := manager.ReadProtected(launcher.Store.journal, "effects.json", launcher.Store.owner, 8*1024*1024)
	if err != nil {
		return false
	}
	state, err := manager.LabObservationState(raw)
	if err != nil || state.Floor != head {
		return false
	}
	matches := 0
	for _, effect := range state.Effects {
		if effect.Account.Generation != generation || !effect.Terminal || effect.Failure != "" || (effect.Request.Op != "user.create" && effect.Request.Op != "user.bump") {
			continue
		}
		request, requestErr := manager.ObjectBytes(effect.Request)
		if requestErr != nil || effect.Request.ID != labString(join, "request_id") || labDigest(request) != labString(join, "request_sha256") {
			return false
		}
		matches++
	}
	return matches == 1
}

func offVMApprovalExpiry(record map[string]any, member string) time.Time {
	field := "expires_at"
	if member == "" {
		field = "valid_until"
	} else {
		record = labMap(record, member)
	}
	instant, _ := time.Parse(time.RFC3339Nano, labString(record, field))
	return instant
}

func labAccessSafe(access map[string]any, now time.Time) bool {
	endpoint := labMap(access, "endpoint")
	for _, value := range endpoint {
		if value != true {
			return false
		}
	}
	for _, name := range []string{"guest_and_control_plane", "vendor_principals"} {
		principals := access[name].([]any)
		if len(principals) == 0 {
			return false
		}
		for _, value := range principals {
			if labString(value.(map[string]any), "controller") != "human" {
				return false
			}
		}
	}
	vendor := labMap(access, "vendor")
	if !labTrue(vendor, "audit_complete") || !labTrue(vendor, "roster_unchanged") {
		return false
	}
	start, _ := time.Parse(time.RFC3339Nano, labString(access, "window_start"))
	end, _ := time.Parse(time.RFC3339Nano, labString(access, "window_end"))
	observed, _ := time.Parse(time.RFC3339Nano, labString(access, "observed_at"))
	return !observed.Before(start) && !now.Before(observed) && now.Before(end)
}
