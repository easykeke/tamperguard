//go:build windows

// sddl-check parses candidate SACL SDDL strings and reports whether the
// resulting security descriptor actually contains a mandatory-label ACE.
// It needs no privileges: the descriptor is parsed in memory.
package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	candidates := []string{
		"S:(ML;OICI;NW;;;S-1-16-16384)",
		"S:(ML;;NW;;;S-1-16-16384)",
		"S:(ML;OICI;NW;;;SY)",
		"S:(ML;;NW;;;HI)",
		"S:(ML;OICI;NW;;;HI)",
		"S:(ML;OICI;NW;;;S-1-16-12288)",
	}
	for _, sddl := range candidates {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			fmt.Printf("SDDL %-38s parse error: %v\n", sddl, err)
			continue
		}
		sacl, defaulted, err := sd.SACL()
		if err != nil {
			fmt.Printf("SDDL %-38s SACL error: %v\n", sddl, err)
			continue
		}
		count := 0
		if sacl != nil {
			count = int(sacl.AceCount)
		}
		fmt.Printf("SDDL %-38s sacl_nil=%v ace_count=%d defaulted=%v\n",
			sddl, sacl == nil, count, defaulted)
		if sacl == nil || count == 0 {
			continue
		}
		for i := 0; i < count; i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(sacl, uint32(i), &ace); err != nil {
				fmt.Printf("    ace[%d]: GetAce error %v\n", i, err)
				continue
			}
			raw := unsafe.Slice((*byte)(unsafe.Pointer(&ace.SidStart)), 32)
			fmt.Printf("    ace[%d]: type=0x%x flags=0x%x size=%d mask=0x%x sid_count=%d raw=% x\n",
				i, ace.Header.AceType, ace.Header.AceFlags, ace.Header.AceSize, ace.Mask, raw[1], raw[:16])
		}
	}
}
