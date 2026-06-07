package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jwlamon/keelix/internal/model"
)

const (
	// walkMaxDepth is the default maximum directory depth explored per Prefix
	// entry. Individual entries may override this via allowEntry.MaxDepth.
	walkMaxDepth = 4
	// walkMaxEntries is the maximum total file entries emitted across all
	// Prefix-entry subtree walks, preventing runaway I/O on large dirs.
	walkMaxEntries = 2000
)

// collectFiles stats every EXACT path in the allowlist and, for Prefix
// entries, performs a bounded subtree walk (depth ≤ walkMaxDepth or the
// entry's MaxDepth, total entries ≤ walkMaxEntries). Symlinks are refused:
// each path is lstated and symlinks are recorded as Exists=false. The walk is
// best-effort: I/O errors are silently dropped and never abort the collection.
//
// Paths that appear in both the exact list and a prefix walk (or in multiple
// overlapping prefix walks) are deduplicated: the first occurrence wins.
func collectFiles(Options) ([]model.FileFact, error) {
	var exactPaths []string
	var prefixEntries []allowEntry

	for _, e := range allowlist {
		if e.Prefix {
			prefixEntries = append(prefixEntries, e)
		} else {
			exactPaths = append(exactPaths, e.Path)
		}
	}

	out := statFiles(exactPaths)

	// Bounded subtree walk for each Prefix entry.
	remaining := walkMaxEntries
	for _, e := range prefixEntries {
		if remaining <= 0 {
			break
		}
		maxD := e.MaxDepth
		if maxD == 0 {
			maxD = walkMaxDepth
		}
		walked, _ := walkPrefix(e.Path, maxD, &remaining)
		out = append(out, walked...)
	}

	// Deduplicate by path: first occurrence wins. This prevents checks from
	// emitting duplicate findings when a path is reachable via both the exact
	// list and one or more overlapping prefix walks (e.g. ~/.claude/settings.json
	// appears as an exact entry AND inside the ~/.claude MaxDepth=1 walk).
	seen := make(map[string]struct{}, len(out))
	deduped := make([]model.FileFact, 0, len(out))
	for _, ff := range out {
		if _, dup := seen[ff.Path]; dup {
			continue
		}
		seen[ff.Path] = struct{}{}
		deduped = append(deduped, ff)
	}

	return deduped, nil
}

// walkPrefix walks the directory rooted at dir, emitting a FileFact for every
// non-directory, non-symlink file found within maxDepth levels. remaining is
// decremented for each file emitted; the walk stops when it reaches zero.
// Errors are silently swallowed (best-effort: the walk is a discovery aid).
func walkPrefix(dir string, maxDepth int, remaining *int) ([]model.FileFact, []model.CollectError) {
	var facts []model.FileFact
	var errs []model.CollectError
	walkDir(dir, 0, maxDepth, remaining, &facts, &errs)
	return facts, errs
}

// walkDir recurses into dir at the given depth, appending FileFacts to facts
// and CollectErrors to errs. It refuses symlinks at every level.
func walkDir(dir string, depth, maxDepth int, remaining *int, facts *[]model.FileFact, errs *[]model.CollectError) {
	if depth > maxDepth || *remaining <= 0 {
		return
	}

	// Lstat the directory itself to confirm it exists and is not a symlink.
	fi, err := os.Lstat(dir)
	if err != nil {
		// Missing or inaccessible — not an error worth recording.
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		// Symlink directory — refuse.
		return
	}
	if !fi.IsDir() {
		// Not a directory; emit a FileFact for the file itself.
		if *remaining <= 0 {
			return
		}
		*remaining--
		*facts = append(*facts, buildFileFact(dir, fi))
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		*errs = append(*errs, model.CollectError{
			Domain: "files",
			Err:    fmt.Sprintf("readdir %s: %v", dir, err),
		})
		return
	}

	for _, de := range entries {
		if *remaining <= 0 {
			return
		}
		child := filepath.Join(dir, de.Name())

		// Use Lstat — not de.Type() — so we detect symlinks reliably.
		cfi, err := os.Lstat(child)
		if err != nil {
			continue
		}
		if cfi.Mode()&os.ModeSymlink != 0 {
			// Record as non-existent (symlink refused).
			*remaining--
			*facts = append(*facts, model.FileFact{Path: child, Exists: false})
			continue
		}
		if cfi.IsDir() {
			walkDir(child, depth+1, maxDepth, remaining, facts, errs)
		} else {
			*remaining--
			*facts = append(*facts, buildFileFact(child, cfi))
		}
	}
}

// buildFileFact constructs a FileFact for a regular (non-symlink) file using
// an already-obtained os.FileInfo.
func buildFileFact(path string, fi os.FileInfo) model.FileFact {
	fact := model.FileFact{
		Path:   path,
		Exists: true,
		Mode:   fmt.Sprintf("%04o", fi.Mode().Perm()),
		Size:   fi.Size(),
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		fact.UID = int(st.Uid)
		fact.GID = int(st.Gid)
	}
	return fact
}

// statFiles lstats each path and returns one FileFact per path, in input order.
// Mode is rendered as a 4-digit octal permission string (e.g. "0600"). Paths
// that do not exist yield FileFact{Exists:false}.
func statFiles(paths []string) []model.FileFact {
	out := make([]model.FileFact, 0, len(paths))
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil {
			out = append(out, model.FileFact{Path: p, Exists: false})
			continue
		}
		fact := model.FileFact{
			Path:   p,
			Exists: true,
			Mode:   fmt.Sprintf("%04o", fi.Mode().Perm()),
			Size:   fi.Size(),
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			fact.UID = int(st.Uid)
			fact.GID = int(st.Gid)
		}
		out = append(out, fact)
	}
	return out
}
