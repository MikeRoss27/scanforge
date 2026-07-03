package version

import "runtime"

var (
	Version = "0.0.1"
	Commit  = "dev"
	Date    = "unknown"
)

func Info() map[string]string {
	return map[string]string{
		"version": Version,
		"commit":  Commit,
		"date":    Date,
		"go":      runtime.Version(),
	}
}
