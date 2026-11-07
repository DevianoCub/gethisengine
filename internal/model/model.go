// Package model contains the data types shared by every extractor and exporter.
package model

import "time"

// Family identifies the engine a browser is built on.
const (
	FamilyChromium = "chromium"
	FamilyFirefox  = "firefox"
)

// Profile is a single browser profile found on the device.
type Profile struct {
	Family     string            `json:"family"`
	BrowserKey string            `json:"browser_key"`
	Browser    string            `json:"browser"`
	Name       string            `json:"name"`
	Path       string            `json:"path"`
	IsDefault  bool              `json:"is_default"`
	Artifacts  map[string]string `json:"artifacts,omitempty"`
}

// Credential is one saved login.
type Credential struct {
	Browser     string     `json:"browser"`
	Profile     string     `json:"profile"`
	URL         string     `json:"url"`
	Realm       string     `json:"realm,omitempty"`
	Username    string     `json:"username,omitempty"`
	Password    string     `json:"password,omitempty"`
	HasPassword bool       `json:"has_password"`
	Created     *time.Time `json:"created,omitempty"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	TimesUsed   int64      `json:"times_used,omitempty"`
	Note        string     `json:"note,omitempty"`
}

// HistoryEntry is one visited URL.
type HistoryEntry struct {
	Browser    string    `json:"browser"`
	Profile    string    `json:"profile"`
	URL        string    `json:"url"`
	Title      string    `json:"title,omitempty"`
	VisitCount int64     `json:"visit_count"`
	LastVisit  time.Time `json:"last_visit"`
}

// Cookie is one HTTP cookie stored by a browser.
type Cookie struct {
	Browser  string    `json:"browser"`
	Profile  string    `json:"profile"`
	Host     string    `json:"host"`
	Name     string    `json:"name"`
	Path     string    `json:"path,omitempty"`
	Value    string    `json:"value,omitempty"`
	Expires  time.Time `json:"expires"`
	Secure   bool      `json:"secure"`
	HTTPOnly bool      `json:"http_only"`
}

// Bookmark is one bookmark entry.
type Bookmark struct {
	Browser string    `json:"browser"`
	Profile string    `json:"profile"`
	Folder  string    `json:"folder,omitempty"`
	Title   string    `json:"title"`
	URL     string    `json:"url"`
	Added   time.Time `json:"added"`
}

// AutofillEntry is one saved form value (name/value pairs).
type AutofillEntry struct {
	Browser string `json:"browser"`
	Profile string `json:"profile"`
	Field   string `json:"field"`
	Value   string `json:"value"`
	Count   int64  `json:"count,omitempty"`
}

// Dataset is the combined output of the dump command.
type Dataset struct {
	SchemaVersion int             `json:"schema_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Hostname      string          `json:"hostname,omitempty"`
	Profiles      []Profile       `json:"profiles"`
	Passwords     []Credential    `json:"passwords"`
	History       []HistoryEntry  `json:"history"`
	Cookies       []Cookie        `json:"cookies"`
	Bookmarks     []Bookmark      `json:"bookmarks"`
	Autofill      []AutofillEntry `json:"autofill"`
	Warnings      []string        `json:"warnings,omitempty"`
}

// SchemaVersion is bumped whenever the JSON layout changes incompatibly.
const SchemaVersion = 1
