package modules

import (
	"bufio"
	"os"
	"time"
)

// TailLines polls path for newly appended complete lines and invokes onLine
// for each one, until stop is closed. It is meant to run in a goroutine
// alongside a subprocess that streams JSONL results to path (e.g. nuclei),
// so callers can surface findings the moment they're written rather than
// waiting for the subprocess to exit. After stop closes, TailLines performs
// one final read to flush any lines written just before the process exited,
// then returns.
//
// The file is allowed to not exist yet (the subprocess may not have created
// it): TailLines simply retries until it appears or stop closes.
func TailLines(path string, stop <-chan struct{}, interval time.Duration, onLine func(line string)) {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}

	var (
		file    *os.File
		reader  *bufio.Reader
		pending string // bytes read past the last complete line, carried to the next poll
	)
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	readAvailable := func() {
		if file == nil {
			f, err := os.Open(path)
			if err != nil {
				return
			}
			file = f
			reader = bufio.NewReader(file)
		}
		for {
			line, err := reader.ReadString('\n')
			if err == nil {
				onLine(pending + line[:len(line)-1])
				pending = ""
				continue
			}
			// Partial line (no trailing newline yet): keep it and retry on
			// the next poll once the writer flushes the rest.
			pending += line
			break
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			readAvailable()
			return
		case <-ticker.C:
			readAvailable()
		}
	}
}
