package cli

import "os"

func writeTestFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
