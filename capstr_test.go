package capstr

import (
	"testing"

	"github.com/bnagy/gapstone"
)

var code = []byte("\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34" +
	"\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91" +
	"\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00" +
	"\x8d\x87\x89\x67\x00\x00\xb4\xc6")

func BenchmarkX86(b *testing.B) {
	engine, err := New(ARCH_X86, MODE_32)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Dis(code, 0x10000, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGapstone(b *testing.B) {
	engine, err := gapstone.New(ARCH_X86, MODE_32)
	if err != nil {
		b.Fatal(err)
	}
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_OFF)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dis, err := engine.Disasm(code, 0x10000, 0)
		if err != nil {
			b.Fatal(err)
		}
		s := make([]string, len(dis))
		for i, v := range dis {
			s[i] = v.Mnemonic + " " + v.OpStr
		}
	}
}
