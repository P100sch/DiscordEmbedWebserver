package main

import (
	"net/http"
	"strings"
	"time"
)

type DataStoreType string

const (
	INVALID  DataStoreType = ""
	NONE     DataStoreType = "none"
	SIMPLE   DataStoreType = "simple"
	FILE     DataStoreType = "file"
	DB       DataStoreType = "db"
	EXTERNAL DataStoreType = "external"
)

type DataStoreConfig struct {
	FilePath         string
	DBDriver         string
	ConnectionString string
	ShellCommand     string
}

type AuthInfo struct {
	Username   string
	Salt       string
	Hash       string
	Iterations int
}

type authToken struct {
	user    string
	expires time.Time
}

type SCRAMState struct {
	username               string
	clientNonce            string
	serverNonce            string
	hash                   string
	clientFirstMessageBare []byte
	expires                time.Time
}

type MultipleErrors []error

func (m MultipleErrors) Error() string {
	var builder = strings.Builder{}
	builder.WriteString("Multiple errors:")
	for _, err := range m {
		builder.WriteString("\n - ")
		builder.WriteString(err.Error())
	}
	return builder.String()
}

type WrappedError struct {
	msg string
	err error
}

func (e WrappedError) Error() string {
	return e.msg + ": " + e.err.Error()
}

type RequestError struct {
	StatusCode int
	Message    string
}

func (re RequestError) StatusText() string {
	switch re.StatusCode {
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 102:
		return "Processing"
	case 103:
		return "Early Hints"
	case 104:
		return "Upload Resumption Supported"
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 202:
		return "Accepted"
	case 203:
		return "Non-Authoritative Information"
	case 204:
		return "No Content"
	case 205:
		return "Reset Content"
	case 206:
		return "Partial Content"
	case 207:
		return "Multi-Status"
	case 208:
		return "Already Reported"
	case 209:
		return "225,Unassigned"
	case 226:
		return "IM Used"
	case 300:
		return "Multiple Choices"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 303:
		return "See Other"
	case 304:
		return "Not Modified"
	case 305:
		return "Use Proxy"
	case 307:
		return "Temporary Redirect"
	case 308:
		return "Permanent Redirect"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 402:
		return "Payment Required"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 406:
		return "Not Acceptable"
	case 407:
		return "Proxy Authentication Required"
	case 408:
		return "Request Timeout"
	case 409:
		return "Conflict"
	case 410:
		return "Gone"
	case 411:
		return "Length Required"
	case 412:
		return "Precondition Failed"
	case 413:
		return "Content Too Large"
	case 414:
		return "URI Too Long"
	case 415:
		return "Unsupported Media Type"
	case 416:
		return "Range Not Satisfiable"
	case 417:
		return "Expectation Failed"
	case 421:
		return "Misdirected Request"
	case 422:
		return "Unprocessable Content"
	case 423:
		return "Locked"
	case 424:
		return "Failed Dependency"
	case 425:
		return "Too Early"
	case 426:
		return "Upgrade Required"
	case 428:
		return "Precondition Required"
	case 429:
		return "Too Many Requests"
	case 431:
		return "Request Header Fields Too Large"
	case 451:
		return "Unavailable For Legal Reasons"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	case 505:
		return "HTTP Version Not Supported"
	case 506:
		return "Variant Also Negotiates"
	case 507:
		return "Insufficient Storage"
	case 508:
		return "Loop Detected"
	case 510:
		return "Not Extended"
	case 511:
		return "Network Authentication Required"
	default:
		return "Error"
	}
}

var noRequestError = RequestError{}

func internalServerErrorWrapper(err error) RequestError {
	return RequestError{StatusCode: http.StatusInternalServerError, Message: err.Error()}
}
