//go:build linux

package sandbox

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// runLandlockProbe is the inner command exec'd by the trampoline child after it
// has applied Landlock + rlimits. It runs IN the confined subprocess (never the
// test process) and prints one PROBE: line per check to stdout so the parent
// test can assert the filesystem/network guarantees. It always exits 0; the
// parent decides pass/fail from the printed lines and the child's applied=
// marker (on stderr).
//
// argv: [home tempDir]
//
//	PROBE: nnp=<0|1>
//	PROBE: rlimit-nofile=<cur>
//	PROBE: home-read=<denied|allowed>
//	PROBE: temp-write=<ok|fail>
//	PROBE: tcp-dial=<denied|refused|allowed|err:...>
//
// The nnp/rlimit lines reflect the trampoline child's applyChildLimits, which
// ran (and is sticky on) THIS subprocess before exec'ing the probe — so the
// limits-applied assertions can be made here instead of in the test process.
func runLandlockProbe(args []string) int {
	if len(args) < 2 {
		fmt.Println("PROBE: error=malformed-args")
		return 2
	}
	home := args[0]
	tempDir := args[1]

	// applyChildLimits ran in this subprocess (via RunSandboxChild) before exec.
	// Read PR_GET_NO_NEW_PRIVS and RLIMIT_NOFILE so the parent can assert them.
	if nnp, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0); errno == 0 {
		fmt.Printf("PROBE: nnp=%d\n", nnp)
	} else {
		fmt.Printf("PROBE: nnp=err:%v\n", errno)
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err == nil {
		fmt.Printf("PROBE: rlimit-nofile=%d\n", rl.Cur)
	} else {
		fmt.Printf("PROBE: rlimit-nofile=err:%v\n", err)
	}

	// 1. $HOME read must be DENIED when Landlock applied (HOME is excluded from
	//    RODirs by design).
	if _, err := os.ReadFile(filepath.Join(home, "secret.txt")); err != nil {
		fmt.Println("PROBE: home-read=denied")
	} else {
		fmt.Println("PROBE: home-read=allowed")
	}

	// 2. The RW tempdir must stay WRITABLE.
	if err := os.WriteFile(filepath.Join(tempDir, "probe-write.txt"), []byte("ok"), 0o600); err != nil {
		fmt.Println("PROBE: temp-write=fail")
	} else {
		fmt.Println("PROBE: temp-write=ok")
	}

	// 3. Outbound TCP must be DENIED on Landlock ABI >=4. We dial 127.0.0.1:1
	//    (nothing listening): EACCES/EPERM => denied by Landlock; ECONNREFUSED =>
	//    the connect() syscall reached the stack (NOT confined).
	conn, dialErr := net.Dial("tcp", "127.0.0.1:1")
	if conn != nil {
		conn.Close()
	}
	switch {
	case dialErr == nil:
		fmt.Println("PROBE: tcp-dial=allowed")
	case strings.Contains(dialErr.Error(), "connection refused"):
		fmt.Println("PROBE: tcp-dial=refused")
	default:
		fmt.Println("PROBE: tcp-dial=denied")
	}
	return 0
}
