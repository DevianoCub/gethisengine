// Package sqlite provides safe, read-only access to browser databases.
//
// Browsers keep their SQLite files open for writing while running and may
// hold platform-specific locks on them. To avoid both lock contention and any
// chance of mutating user data we copy the database (plus its -wal, -shm and
// -journal sidecars) into a private temporary directory and open that copy in
// immutable read-only mode.
package sqlite

import (
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// OpenReadOnly copies path (and sidecars) to a temporary directory and opens
// the copy. The returned cleanup function closes the database and removes the
// temporary files; callers must always invoke it.
func OpenReadOnly(path string) (*sql.DB, func(), error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, nil, fmt.Errorf("open %s: is a directory", path)
	}

	tmpDir, err := os.MkdirTemp("", "gethisengine-sqlite-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanupFiles := func() { _ = os.RemoveAll(tmpDir) }

	dst := filepath.Join(tmpDir, filepath.Base(path))
	sidecars := []string{"", "-wal", "-shm", "-journal"}
	for _, suffix := range sidecars {
		if err := copyIfExists(path+suffix, dst+suffix); err != nil {
			cleanupFiles()
			return nil, nil, err
		}
	}

	dsn := (&url.URL{
		Scheme:   "file",
		Path:     dst,
		RawQuery: "mode=ro&immutable=1",
	}).String()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		cleanupFiles()
		return nil, nil, fmt.Errorf("open sqlite copy: %w", err)
	}

	cleanup := func() {
		_ = db.Close()
		cleanupFiles()
	}

	if err := db.Ping(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read sqlite copy: %w", err)
	}
	return db, cleanup, nil
}

func copyIfExists(src, dst string) error {
	in, err := openSource(src)
	if err != nil {
		if isNotExist(err) {
			return nil
		}
		return fmt.Errorf("copy %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy %s: %w", src, err)
	}
	return out.Close()
}

// HasTable reports whether the database contains a table with the given name.
func HasTable(db *sql.DB, table string) bool {
	var name string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name = ?", table,
	).Scan(&name)
	return err == nil
}

// HasColumn reports whether table has a column with the given name.
func HasColumn(db *sql.DB, table, column string) bool {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return false
	}
	defer rows.Close()

	var (
		cid     int
		name    string
		ctype   string
		notnull int
		dflt    any
		pk      int
	)
	for rows.Next() {
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == column {
			return true
		}
	}
	return false
}
