package cvss

import "testing"

func FuzzCvss3xUnmarshalJSONNeverPanics(f *testing.F) {
	f.Add([]byte(`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`))
	f.Add([]byte(`null`))
	f.Add([]byte(`123`))
	f.Add([]byte(`{"vectorString":"not a vector"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var cv Cvss3x
		if err := cv.UnmarshalJSON(data); err != nil {
			return
		}
		// Successful decoding must produce a serializable value.
		if _, err := cv.MarshalJSON(); err != nil {
			t.Fatalf("successful JSON decode could not be encoded: %v", err)
		}
	})
}
