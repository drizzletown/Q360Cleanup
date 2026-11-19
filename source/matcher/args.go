package matcher

import "unicode"

// ParseWindowsCommandLine tokenizes a Windows command line without invoking a shell.
// It handles backslash-quote escaping used by CommandLineToArgvW.
func ParseWindowsCommandLine(s string) []string {
	r := []rune(s)
	out := make([]string, 0, 8)
	i := 0
	for i < len(r) {
		for i < len(r) && unicode.IsSpace(r[i]) {
			i++
		}
		if i == len(r) {
			break
		}
		arg := make([]rune, 0, 64)
		inQuotes := false
		for i < len(r) {
			c := r[i]
			if unicode.IsSpace(c) && !inQuotes {
				break
			}
			if c == '\\' {
				j := i
				for j < len(r) && r[j] == '\\' {
					j++
				}
				n := j - i
				if j < len(r) && r[j] == '"' {
					for k := 0; k < n/2; k++ {
						arg = append(arg, '\\')
					}
					if n%2 == 1 {
						arg = append(arg, '"')
						i = j + 1
						continue
					}
					i = j
					continue // next iteration will process the quote
				}
				for k := 0; k < n; k++ {
					arg = append(arg, '\\')
				}
				i = j
				continue
			}
			if c == '"' {
				if inQuotes && i+1 < len(r) && r[i+1] == '"' {
					arg = append(arg, '"')
					i += 2
					continue
				}
				inQuotes = !inQuotes
				i++
				continue
			}
			arg = append(arg, c)
			i++
		}
		out = append(out, string(arg))
		for i < len(r) && unicode.IsSpace(r[i]) {
			i++
		}
	}
	return out
}
