package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// iwGameFilter is the dummy game filter the other conversion tests use.
func iwGameFilter() GameFilter { return GameFilter{TCP: "12", UDP: "12"} }

// iwBat wraps a flag list into a one-profile .bat.
func iwBat(flags string) []byte {
	return []byte("start \"%BIN%winws.exe\" --wf-tcp=443 ^\n--filter-tcp=443 " + flags + "\n")
}

// iwConvert converts a one-profile .bat and returns the single profile's ops.
func iwConvert(t *testing.T, flags string) (*Result, []strategy.OpSpec) {
	t.Helper()
	res, err := Convert("x.bat", iwBat(flags), iwGameFilter())
	if err != nil {
		t.Fatalf("Convert(%s): %v", flags, err)
	}
	if len(res.File.Profiles) != 1 {
		t.Fatalf("got %d profiles, want 1", len(res.File.Profiles))
	}
	return res, res.File.Profiles[0].Ops
}

// iwFindOp returns the OpSpec for the named op.
func iwFindOp(t *testing.T, ops []strategy.OpSpec, name string) strategy.OpSpec {
	t.Helper()
	for _, o := range ops {
		if o.Op == name {
			return o
		}
	}
	t.Fatalf("no %q op among %d ops", name, len(ops))
	return strategy.OpSpec{}
}

// iwLoad writes the converter's own output and puts it through the real loader,
// which is the only proof that what batconv emits is what the daemon can read.
func iwLoad(t *testing.T, res *Result) *strategy.Strategy {
	t.Helper()
	path := filepath.Join(t.TempDir(), res.OutName)
	if err := os.WriteFile(path, []byte(res.Marshal()), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	s, err := strategy.Load(path, strategy.LoadOpts{Caps: desync.FullCaps()})
	if err != nil {
		t.Fatalf("the generated TOML does not load: %v\n--- file ---\n%s", err, res.Marshal())
	}
	return s
}

// TestConvertAcceptsEveryIPIDMode covers the modes that used to be refused with
// "seqgroup has no IPIDMode". Both exist now (desync.IPIDSeqGroup / IPIDSame) and
// the loader's parseIPIDMode accepts their spelling, so refusing them here would
// make a .bat unconvertible for no reason.
func TestConvertAcceptsEveryIPIDMode(t *testing.T) {
	for _, tc := range []struct{ flag, want string }{
		{"zero", "zero"},
		{"seq", "seq"},
		{"seqgroup", "seqgroup"},
		{"same", "same"},
		{"rnd", "random"},
		{"random", "random"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			res, ops := iwConvert(t, "--dpi-desync=multisplit --ip-id="+tc.flag)
			if got := iwFindOp(t, ops, "ip_id").Mode; got != tc.want {
				t.Errorf("--ip-id=%s produced mode %q, want %q", tc.flag, got, tc.want)
			}
			// The emitted spelling must be one the loader really takes.
			iwLoad(t, res)
		})
	}
	if _, err := Convert("x.bat", iwBat("--dpi-desync=multisplit --ip-id=nonsense"), iwGameFilter()); err == nil ||
		!strings.Contains(err.Error(), "unsupported --ip-id mode") {
		t.Errorf("an unknown --ip-id mode must still be refused, got %v", err)
	}
}

// TestConvertCarriesWSSizeCutoff pins the other stale gap: --wssize-cutoff used
// to die on "unknown winws flag". It has no TOML field of its own (types.go is a
// contract file), so it rides the wssize op's Mod under the key the loader reads.
func TestConvertCarriesWSSizeCutoff(t *testing.T) {
	res, ops := iwConvert(t, "--dpi-desync=multisplit --wssize=128:6 --wssize-cutoff=d2")
	ws := iwFindOp(t, ops, "wssize")
	if ws.WSSize != "128:6" {
		t.Errorf("wssize = %q, want %q", ws.WSSize, "128:6")
	}
	if got := ws.Mod["cutoff"]; got != "d2" {
		t.Errorf("mod.cutoff = %q, want %q (mod=%v)", got, "d2", ws.Mod)
	}

	// And it has to survive the round trip through the generated file.
	var found bool
	for _, p := range iwLoad(t, res).Profiles {
		for _, co := range p.Ops {
			if co.Op.Name() != "wssize" {
				continue
			}
			found = true
			if co.Params.WSSizeCutoffKind != 'd' || co.Params.WSSizeCutoffN != 2 {
				t.Errorf("cutoff compiled to kind %q n %d, want kind 'd' n 2",
					co.Params.WSSizeCutoffKind, co.Params.WSSizeCutoffN)
			}
			if co.Params.WSSize != 128 {
				t.Errorf("wssize compiled to %d, want 128", co.Params.WSSize)
			}
		}
	}
	if !found {
		t.Error("no wssize op survived the load")
	}
}

// TestConvertRefusesWSSizeCutoffWithoutWSSize keeps the converter's own rule: a
// knob no op consumes is a quietly weaker strategy, so it must fail loudly. The
// cutoff rides the wssize op, so without --wssize there is nothing to ride.
func TestConvertRefusesWSSizeCutoffWithoutWSSize(t *testing.T) {
	_, err := Convert("x.bat", iwBat("--dpi-desync=multisplit --wssize-cutoff=d2"), iwGameFilter())
	if err == nil || !strings.Contains(err.Error(), "--wssize-cutoff") {
		t.Fatalf("want an unconsumed-knob error naming --wssize-cutoff, got %v", err)
	}
}

// TestConvertRejectsABadWSSizeCutoff checks the value is validated at conversion
// time rather than blowing up later at strategy load.
func TestConvertRejectsABadWSSizeCutoff(t *testing.T) {
	_, err := Convert("x.bat", iwBat("--dpi-desync=multisplit --wssize=128 --wssize-cutoff=zz9"), iwGameFilter())
	if err == nil || !strings.Contains(err.Error(), "--wssize-cutoff") {
		t.Fatalf("want a validation error naming --wssize-cutoff, got %v", err)
	}
}
