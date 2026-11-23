package seal

import (
	"regexp"
	"strings"
	"testing"

	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// avoidWords is DEMO-DESIGN §6's "Avoid" column.
var avoidWords = []string{
	"attestation", "quote", "report",
	"measurement", "hash", "digest",
	"VCEK", "ARK", "ASK", "PSP",
	"nvattest", "CC mode", "NRAS",
	"TEE", "enclave", "CVM",
}

var hexString = regexp.MustCompile(`(?i)\b(0x)?[0-9a-f]{6,}\b`)

func mainScreenTexts() []string {
	texts := []string{messageSent, messageUnreachable, messageHardware, messageListUnchecked, messageSoftware, messageGPU, messageUnfinished}
	for _, name := range []TickName{Hardware, Software, GPU} {
		for _, status := range []Status{Pass, Fail, NotChecked} {
			texts = append(texts, tickText(name, status))
		}
	}
	return texts
}

func TestPlainWording(t *testing.T) {
	for _, text := range mainScreenTexts() {
		if hexString.MatchString(text) {
			t.Errorf("%q contains a hexadecimal string", text)
		}
		for _, word := range avoidWords {
			if regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`).MatchString(text) {
				t.Errorf("%q contains %q from the Avoid column", text, word)
			}
		}
	}
}

func TestMessages(t *testing.T) {
	tests := []struct {
		hardware, software, gpu Tick
		want                    string
	}{
		{Tick{Status: Pass}, Tick{Status: Fail, Reason: reason.MeasurementUnknown}, Tick{Status: NotChecked}, "Not sent: this server isn't running the approved software"},
		{Tick{Status: Fail, Reason: reason.SignatureInvalid}, Tick{Status: NotChecked}, Tick{Status: NotChecked}, messageHardware},
		{Tick{Status: Fail, Reason: reason.Timeout}, Tick{Status: NotChecked}, Tick{Status: NotChecked}, messageUnreachable},
		{Tick{Status: Fail, Reason: reason.AllowlistUnverified}, Tick{Status: NotChecked}, Tick{Status: NotChecked}, messageListUnchecked},
		{Tick{Status: Pass}, Tick{Status: Pass}, Tick{Status: Fail, Reason: reason.GPUCount}, messageGPU},
		{Tick{Status: Fail, Reason: reason.InternalError}, Tick{Status: NotChecked}, Tick{Status: NotChecked}, messageUnfinished},
	}
	for _, tt := range tests {
		r := newResult()
		r.Ticks = Ticks{Hardware: tt.hardware, Software: tt.software, GPU: tt.gpu}
		r.finish([]byte("key"))
		if r.Message != tt.want || r.Permitted {
			t.Errorf("%+v: got %q, permitted %v; want %q", r.Ticks, r.Message, r.Permitted, tt.want)
		}
		if _, ok := r.SendKey(); ok {
			t.Errorf("%+v: a refused result returned a key", r.Ticks)
		}
	}
}

func TestSendKeyOnce(t *testing.T) {
	r := newResult()
	r.pass(Hardware)
	r.pass(Software)
	r.pass(GPU)
	r.finish([]byte("attested key"))
	if key, ok := r.SendKey(); !ok || string(key) != "attested key" {
		t.Fatalf("SendKey() = %q, %v", key, ok)
	}
	if key, ok := r.SendKey(); ok || key != nil {
		t.Errorf("second SendKey() = %q, %v", key, ok)
	}
	if strings.Contains(r.Message, "Not sent") {
		t.Errorf("message %q", r.Message)
	}
}

func TestNotCheckedCountsAsFailure(t *testing.T) {
	r := newResult()
	r.pass(Hardware)
	r.pass(Software)
	r.finish([]byte("key"))
	if r.Permitted {
		t.Error("a not_checked GPU tick permitted sending")
	}
}
