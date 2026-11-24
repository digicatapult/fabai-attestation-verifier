package seal

import "github.com/digicatapult/fabai-attestation-verifier/reason"

// Main-screen wording. It never contains hex, hashes or vendor key names.

// tickLabels are the seal panel's three lines.
var tickLabels = map[TickName]string{
	Hardware: "Genuine AMD secure hardware",
	Software: "Approved software",
	GPU:      "NVIDIA GPU in secure mode",
}

var statusSuffix = map[Status]string{
	Pass:       "",
	Fail:       ": failed",
	NotChecked: ": not checked",
}

func tickText(name TickName, status Status) string {
	return tickLabels[name] + statusSuffix[status]
}

// Headlines for the Protected pane.
const (
	messageSent          = "Seal check passed"
	messageUnreachable   = "Not sent: the seal check couldn't reach this server"
	messageHardware      = "Not sent: this server couldn't show it's genuine AMD secure hardware"
	messageListUnchecked = "Not sent: the list of approved software couldn't be checked"
	messageSoftware      = "Not sent: this server isn't running the approved software"
	messageGPU           = "Not sent: this server's NVIDIA GPU isn't in secure mode"
	messageUnfinished    = "Not sent: the seal check didn't finish"
)

func message(r *Result) string {
	if r.Permitted {
		return messageSent
	}
	hw, sw := r.Ticks.Hardware, r.Ticks.Software
	switch {
	case hw.Reason == reason.InternalError || sw.Reason == reason.InternalError || r.Ticks.GPU.Reason == reason.InternalError:
		return messageUnfinished
	case hw.Status != Pass && isFetchReason(hw.Reason):
		return messageUnreachable
	case hw.Status != Pass && hw.Reason == reason.AllowlistUnverified:
		return messageListUnchecked
	case hw.Status != Pass:
		return messageHardware
	case sw.Status != Pass:
		return messageSoftware
	default:
		return messageGPU
	}
}

func isFetchReason(code reason.Code) bool {
	switch code {
	case reason.FetchFailed, reason.Timeout, reason.BadStatus, reason.TooLarge:
		return true
	}
	return false
}
