package amd

import (
	"bytes"
	"testing"

	"github.com/tinfoilsh/go-sev-guest/verify/trust"
)

// TestPinnedRootsMatchGoSevGuest compares each pinned ARK with the copy
// go-sev-guest embeds.
func TestPinnedRootsMatchGoSevGuest(t *testing.T) {
	for _, product := range []string{Milan, Genoa, Turin} {
		pinned, ok := PinnedARK(product)
		if !ok {
			t.Fatalf("no pinned root for %s", product)
		}
		embedded, err := trust.GetDefaultRootCerts(product)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pinned.Raw, embedded.ProductCerts.Ark.Raw) {
			t.Errorf("pinned %s ARK differs from go-sev-guest's", product)
		}
		if err := pinned.CheckSignatureFrom(pinned); err != nil {
			t.Errorf("%s ARK isn't self-signed: %v", product, err)
		}
	}
}

func TestPinnedDigestRefusesOtherRoot(t *testing.T) {
	if _, err := parsePinnedARK(Turin, arkGenoaPEM); err == nil {
		t.Error("the Genoa ARK was accepted as the Turin root")
	}
}

func TestDecodeTCBTurin(t *testing.T) {
	tcb, err := DecodeTCB(Turin, 0x4800000004010101)
	if err != nil {
		t.Fatal(err)
	}
	if tcb.FMC == nil || *tcb.FMC != 1 || tcb.Bootloader != 1 || tcb.TEE != 1 || tcb.SNP != 4 || tcb.Microcode != 0x48 {
		t.Errorf("got %s", tcb)
	}
	if ok, component := tcb.AtLeast(TCB{SNP: 5}); ok || component != "snp" {
		t.Errorf("AtLeast(SNP 5) = %v, %q", ok, component)
	}
}

func TestDecodeTCBGenoa(t *testing.T) {
	tcb, err := DecodeTCB(Genoa, 0xd317000000000304)
	if err != nil {
		t.Fatal(err)
	}
	if tcb.FMC != nil || tcb.Bootloader != 4 || tcb.TEE != 3 || tcb.SNP != 0x17 || tcb.Microcode != 0xd3 {
		t.Errorf("got %s", tcb)
	}
}

func TestOfflineGetter(t *testing.T) {
	g := OfflineGetter{CRLURL: CRLURL(Turin), CRLDER: []byte{1, 2, 3}}
	if got, err := g.Get("https://kdsintf.amd.com/vcek/v1/Turin/crl"); err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Errorf("CRL URL: %v, %v", got, err)
	}
	for _, url := range []string{"https://kdsintf.amd.com/vcek/v1/Turin/cert_chain", "https://kdsintf.amd.com/vcek/v1/Genoa/crl", "https://example.com/"} {
		if _, err := g.Get(url); err == nil {
			t.Errorf("%s was served", url)
		}
	}
}
