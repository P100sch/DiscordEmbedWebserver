package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	rand2 "math/rand"
	"net/http"
	"slices"
	"strings"
	"time"
)

func simpleLogin(encoded string) (bool, string, RequestError) {
	var buffer = make([]byte, 255)
	var data, _ = splitFirst(encoded, ' ')
	var decoder = base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))
	var (
		decoded []byte
		count   int
		err     error
	)
	for count, err = decoder.Read(buffer); count == len(buffer); count, err = decoder.Read(buffer) {
		decoded = append(decoded, buffer...)
	}
	if err != nil && err != io.EOF {
		return false, "", RequestError{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("could not decode data: %s", err.Error())}
	}
	username, password := splitFirst(string(append(buffer, decoded[:count]...)), ':')
	ok, err := validateSimpleLogin(username, password)
	if err != nil {
		return false, "", RequestError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("could not load login: %s", err.Error())}
	}
	return ok, "", noRequestError
}

type triStateBool byte

const (
	FALSE triStateBool = iota
	CONTINUE
	TRUE
)

func scramLogin(msg string) (ok triStateBool, id, response, username string, requestError RequestError) {
	var data64 string
	for parameter, rest := splitFirst(msg, ','); strings.TrimSpace(parameter) != ""; parameter, rest = splitFirst(rest, ',') {
		name, value := parseParameter(parameter)
		switch strings.ToLower(name) {
		case "sid":
			id = value
		case "data":
			data64 = value
		}
	}
	if data64 == "" {
		return FALSE, "", "", "", RequestError{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("auth parameter missing: data")}
	}
	data, err := base64.StdEncoding.DecodeString(data64)
	if err != nil {
		return FALSE, "", "", "", RequestError{StatusCode: http.StatusBadRequest, Message: "could not decode data: " + err.Error()}
	}
	if id != "" {
		var authOk bool
		authOk, response, username, requestError = scramAuthenticate(id, string(data))
		if authOk {
			ok = TRUE
		}
		return ok, id, response, username, requestError
	} else {
		id, response, requestError = scramRespondWithNonceSaltAndIterations(data)
		return CONTINUE, id, response, username, requestError
	}
}

func scramRespondWithNonceSaltAndIterations(data []byte) (id, response string, requestError RequestError) {
	var scramState = SCRAMState{expires: time.Now().Add(time.Minute * 5)}
	var err error

	parameter, rest := splitFirst(string(data), ',')
	if parameter != "n" {
		return "", "", RequestError{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("invalid channel binding flag: %s", parameter)}
	}
	parameter, rest = splitFirst(rest, ',') //discard irrelevant parameter

	var buffer = make([]byte, 8)
	_, _ = rand.Read(buffer)
	id = hex.EncodeToString(buffer)

	var random = rand2.New(rand2.NewSource(time.Now().UnixNano()))
	var builder = strings.Builder{}
	for length := 0; length < 18; {
		var character = random.Intn(127-33) + 33
		if character != ',' {
			_ = builder.WriteByte(byte(character))
			length++
		}
	}
	scramState.serverNonce = builder.String()

	var (
		salt       string
		iterations int
		validUser  bool
	)
	for parameter, rest = splitFirst(rest, ','); strings.TrimSpace(parameter) != ""; parameter, rest = splitFirst(rest, ',') {
		name, value := parseParameter(parameter)
		if name == "n" {
			if value == "" {
				return "", "", RequestError{StatusCode: http.StatusBadRequest, Message: "name cannot be empty"}
			}
			salt, iterations, validUser, err = getSaltAndIterations(value)
			if err != nil {
				return "", "", RequestError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("an error occurred retrieving salt and iteration count: %s", err.Error())}
			} else if !validUser {
				var hash = fnv.New64a()
				_, _ = hash.Write([]byte(value))
				var seed, _ = binary.Varint(hash.Sum(nil))
				var random = rand2.New(rand2.NewSource(seed))
				iterations = 600000 + random.Intn(100000)
				var buffer = make([]byte, 64)
				_, _ = random.Read(buffer)
				salt = base64.StdEncoding.EncodeToString(buffer)
			}
			scramState.username = value
		} else if name == "r" {
			if value == "" {
				return "", "", RequestError{StatusCode: http.StatusBadRequest, Message: "nonce cannot be empty"}
			}
			scramState.clientNonce = value
		}
	}
	if scramState.clientNonce == "" || scramState.username == "" {
		var missing = ""
		if scramState.clientNonce == "" {
			missing = ",r"
		}
		if scramState.username == "" {
			missing += ",n"
		}
		return "", "", RequestError{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("auth data parameter missing: %s", missing[1:])}
	}
	if validUser {
		scramState.clientFirstMessageBare = data
		if !tryLockingWithTimeout(nonceMutex.TryLock, time.Second*10) {
			return "", "", RequestError{StatusCode: http.StatusLocked, Message: "auth data already locked"}
		}
		scramStates[id] = scramState
		nonceMutex.Unlock()
	}
	return id, firstServerMessage(scramState.clientNonce+scramState.serverNonce, salt, iterations), noRequestError
}

func scramAuthenticate(id, data string) (ok bool, response, username string, requestError RequestError) {
	var scramState SCRAMState
	if !tryLockingWithTimeout(nonceMutex.TryRLock, time.Second*10) {
		return false, "", "", RequestError{StatusCode: http.StatusLocked, Message: "auth data already locked"}
	}
	defer nonceMutex.RUnlock()
	if scramState, ok = scramStates[id]; !ok {
		return
	}
	var clientFinalMessageBuilder = strings.Builder{}
	var proof string
outside:
	for parameter, rest := splitFirst(data, ','); strings.TrimSpace(parameter) != ""; parameter, rest = splitFirst(rest, ',') {
		name, value := parseParameter(parameter)
		switch name {
		case "c":
		case "r":
			if value != scramState.clientNonce+scramState.serverNonce {
				return false, "", "", RequestError{StatusCode: http.StatusBadRequest, Message: "nonce differs expected nonce"}
			}
		case "p":
			if value == "" {
				return false, "", "", RequestError{StatusCode: http.StatusBadRequest, Message: "proof can not be empty"}
			}
			proof = value
			break outside
		}
		clientFinalMessageBuilder.WriteByte(',')
		clientFinalMessageBuilder.WriteString(parameter)
	}
	if len(proof) == 0 {
		return false, "", "", RequestError{StatusCode: http.StatusBadRequest, Message: "auth data parameter missing: p"}
	}
	info, ok, err := getAuthInfo(scramState.username)
	if err != nil {
		return false, "", "", internalServerErrorWrapper(err)
	}
	if !ok {
		return
	}
	var saltedPassword = make([]byte, base64.StdEncoding.DecodedLen(len(info.Hash)))
	if _, err := base64.StdEncoding.Decode(saltedPassword, []byte(info.Hash)); err != nil {
		return false, "", "", internalServerErrorWrapper(err)
	}
	var hashBuilder = hmac.New(sha256.New, saltedPassword)
	hashBuilder.Write([]byte("Client Key"))
	var clientKey = hashBuilder.Sum(nil)
	hashBuilder = sha256.New()
	hashBuilder.Write(clientKey)
	var storedKey = hashBuilder.Sum(nil)
	var authMessage = slices.Concat(scramState.clientFirstMessageBare, []byte(","), []byte(firstServerMessage(scramState.clientNonce+scramState.serverNonce, info.Salt, info.Iterations)), []byte(","), []byte(clientFinalMessageBuilder.String()[1:]))
	hashBuilder = hmac.New(sha256.New, storedKey)
	hashBuilder.Write(authMessage)
	var recomputedProof = hashBuilder.Sum(nil)
	for i, octet := range clientKey {
		recomputedProof[i] = recomputedProof[i] ^ octet
	}
	if proof != base64.StdEncoding.EncodeToString(recomputedProof) {
		ok = false
		return
	}

	hashBuilder = hmac.New(sha256.New, saltedPassword)
	hashBuilder.Write([]byte("Server Key"))
	hashBuilder = hmac.New(sha256.New, hashBuilder.Sum(nil))
	hashBuilder.Write(authMessage)
	return true, "v=" + base64.StdEncoding.EncodeToString(hashBuilder.Sum(nil)), scramState.username, noRequestError
}

func firstServerMessage(nonce, salt string, iterations int) string {
	return fmt.Sprintf("r=%s,s=%s,i=%d", nonce, salt, iterations)
}
