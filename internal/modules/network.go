package modules

import "strings"

// ProxyArgs returns the flag/value pair to append to a command's args when a
// proxy is configured, or nil otherwise. flag is the tool-specific proxy
// option (e.g. "-proxy", "-x", "--proxy").
func (c *RunContext) ProxyArgs(flag string) []string {
	if c.Proxy == "" {
		return nil
	}
	return []string{flag, c.Proxy}
}

// ProxyHost returns the configured proxy without its scheme, for tools that
// expect a bare host[:port] rather than a URL (e.g. whatweb's --proxy).
func (c *RunContext) ProxyHost() string {
	value := c.Proxy
	for _, prefix := range []string{"http://", "https://", "socks5://", "socks5h://", "socks4://"} {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	return value
}

// HeaderArgs returns repeated flag/value pairs, one per configured header,
// suitable for tools that accept custom headers as repeatable CLI flags
// (e.g. "-H" "Authorization: Bearer ...").
func (c *RunContext) HeaderArgs(flag string) []string {
	if len(c.Headers) == 0 {
		return nil
	}
	args := make([]string, 0, len(c.Headers)*2)
	for _, header := range c.Headers {
		args = append(args, flag, header)
	}
	return args
}
