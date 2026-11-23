package seal

import (
	"sync"

	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// Status is a tick's outcome. NotChecked counts as a failure everywhere.
type Status string

// Tick outcomes.
const (
	Pass       Status = "pass"
	Fail       Status = "fail"
	NotChecked Status = "not_checked"
)

// TickName identifies one of the three ticks.
type TickName string

// The three ticks, in evaluation order.
const (
	Hardware TickName = "hardware"
	Software TickName = "software"
	GPU      TickName = "gpu"
)

// Tick is one tick's outcome, its stable reason code when it didn't pass,
// and its main-screen text.
type Tick struct {
	Status Status      `json:"status"`
	Reason reason.Code `json:"reason,omitempty"`
	Text   string      `json:"text"`
}

// Ticks holds the three ticks.
type Ticks struct {
	Hardware Tick `json:"hardware"`
	Software Tick `json:"software"`
	GPU      Tick `json:"gpu"`
}

// Result is one check's outcome. It permits a send only if all three ticks
// pass; only then does SendKey return the attested key, and only once.
type Result struct {
	Ticks     Ticks  `json:"ticks"`
	Permitted bool   `json:"permitted"`
	Message   string `json:"message"`
	// EntryID is the matched allowlist entry, set when the software tick passes.
	EntryID string `json:"entryId,omitempty"`
	Detail  Detail `json:"detail"`

	key *onceKey
	// pendingKey holds the channel key until finish decides.
	pendingKey []byte
}

type onceKey struct {
	mu  sync.Mutex
	key []byte
}

// SendKey returns the key to seal this one request to, if the result
// permits sending. A second call returns nothing, so a key can't be reused
// by accident.
func (r *Result) SendKey() ([]byte, bool) {
	if r == nil || !r.Permitted || r.key == nil {
		return nil, false
	}
	r.key.mu.Lock()
	defer r.key.mu.Unlock()
	key := r.key.key
	r.key.key = nil
	return key, key != nil
}

func newResult() *Result {
	r := &Result{}
	r.Ticks.Hardware = Tick{Status: NotChecked}
	r.Ticks.Software = Tick{Status: NotChecked}
	r.Ticks.GPU = Tick{Status: NotChecked}
	return r
}

func (r *Result) tick(name TickName) *Tick {
	switch name {
	case Hardware:
		return &r.Ticks.Hardware
	case Software:
		return &r.Ticks.Software
	default:
		return &r.Ticks.GPU
	}
}

// fail records err on the named tick, with its reason code and, for the
// experts view, its message.
func (r *Result) fail(name TickName, err error) {
	t := r.tick(name)
	t.Status = Fail
	t.Reason = reason.CodeOf(err)
	r.Detail.Errors = append(r.Detail.Errors, string(name)+": "+err.Error())
}

func (r *Result) pass(name TickName) {
	t := r.tick(name)
	t.Status = Pass
	t.Reason = ""
}

// finish sets the decision and the main-screen text. The key is attached
// only when every tick passed.
func (r *Result) finish(key []byte) {
	r.Permitted = r.Ticks.Hardware.Status == Pass && r.Ticks.Software.Status == Pass && r.Ticks.GPU.Status == Pass
	if r.Permitted && len(key) > 0 {
		r.key = &onceKey{key: key}
	} else {
		r.Permitted = false
	}
	r.pendingKey = nil
	for _, name := range []TickName{Hardware, Software, GPU} {
		t := r.tick(name)
		t.Text = tickText(name, t.Status)
	}
	r.Message = message(r)
}
