package buggy

import "testing"

func FailNested0(t *testing.T) {
	t.Fatalf("%s", "yeet")
}
func FailNested1(t *testing.T) {
	FailNested0(t)
}
func FailNested2(t *testing.T) {
	FailNested1(t)
}

func FuzzBuggy(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 0 && data[0] == 'f' {
			if len(data) > 1 && data[1] == 'u' {
				if len(data) > 2 && data[2] == 'z' {
					if len(data) > 3 && data[3] == 'z' {
						FailNested2(t)
					}
				}
			}
		}
	})
}
