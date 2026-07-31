package desync

import (
	"fmt"
	"sort"
	"sync"
)

// Factory builds a fresh Op instance. Ops are stateless: all per-invocation
// input arrives through Ctx, so one instance may serve every flow.
type Factory func() Op

var (
	regMu sync.RWMutex
	reg   = map[string]Factory{}
)

// Register adds an op under its --dpi-desync spelling. Called from init() in
// each op's file; panics on a duplicate name so a typo fails loudly at start.
func Register(name string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := reg[name]; dup {
		panic("desync: duplicate op registration: " + name)
	}
	reg[name] = f
}

// Alias registers name as another spelling of an already registered op.
// zapret keeps legacy aliases: split->fakedsplit, disorder->fakeddisorder,
// split2->multisplit, disorder2->multidisorder.
func Alias(name, target string) {
	regMu.Lock()
	defer regMu.Unlock()
	f, ok := reg[target]
	if !ok {
		panic("desync: alias " + name + " -> unknown op " + target)
	}
	if _, dup := reg[name]; dup {
		panic("desync: duplicate op registration: " + name)
	}
	reg[name] = f
}

// Lookup instantiates the op registered under name.
func Lookup(name string) (Op, error) {
	regMu.RLock()
	f, ok := reg[name]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown desync op %q (known: %v)", name, Names())
	}
	return f(), nil
}

// Names lists every registered op, sorted.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(reg))
	for n := range reg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// FakeFor picks the fake payload matching an L7 class, mirroring nfqws'
// --dpi-desync-fake-* selection. index cycles through multi-valued sets so
// repeats can rotate payloads the way winws does with several --fake-discord.
func (f FakeSet) FakeFor(kind string, index int) []byte {
	pick := func(s [][]byte) []byte {
		if len(s) == 0 {
			return nil
		}
		return s[index%len(s)]
	}
	switch kind {
	case "tls":
		return f.TLS
	case "http":
		return f.HTTP
	case "quic":
		return f.QUIC
	case "discord":
		return pick(f.Discord)
	case "stun":
		return pick(f.STUN)
	case "unknown_udp", "unknown":
		return pick(f.UnknownUDP)
	case "syndata":
		return f.SynData
	}
	return nil
}
