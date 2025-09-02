package main

import (
	"time"
)

func splitFirst(str string, delimiter uint8) (string, string) {
	var i = 0
	for ; i < len(str) && str[i] != delimiter; i++ {
	}
	if i == len(str) {
		return str, ""
	} else if i+1 == len(str) {
		return str[:i], ""
	} else if i == 0 && len(str) < 2 {
		return "", ""
	} else if i == 0 {
		return "", str[1:]
	} else {
		return str[:i], str[i+1:]
	}
}

func parseParameter(str string) (name, value string) {
	var (
		start        = 0
		insideString = false
		inSeparator  = true

		i    int
		char int32
	)
outer:
	for i, char = range str {
		switch char {
		case ' ', '\n', '\r', '\t', ',':
			if !inSeparator || char == ',' {
				name = str[start:i]
				return
			}
		case '=':
			name = str[start:i]
			break outer
		default:
			if inSeparator {
				start = i
				inSeparator = false
			}
		}
	}
	start = i + 1
	var valueStart = start
	for i, char = range str[start:] {
		switch char {
		case ' ', '\n', '\r', '\t', ',':
			if !insideString {
				value = str[valueStart : start+i]
				return
			}
		case '"':
			if i == 0 {
				valueStart += 1
				inSeparator = false
				insideString = true
			} else if insideString {
				value = str[valueStart : start+i]
				return
			}
		default:
		}
	}
	value = str[valueStart:]
	return
}

func tryLockingWithTimeout(tryLock func() bool, timeout time.Duration) bool {
	var ticker = time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()
	for i := 0; i < int(timeout/(time.Millisecond*100)); i++ {
		if tryLock() {
			return true
		}
		<-ticker.C
	}
	return false
}
