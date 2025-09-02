package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"html/template"
	"io"
	"log"
	rand2 "math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/google/uuid"
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

var Config = struct {
	Host            string
	Port            string
	Hostname        string
	BaseUrl         string
	SslCert         string
	SslKey          string
	LogoutTimeout   time.Duration
	Auth            DataStoreType
	AuthConfig      DataStoreConfig
	DataStore       DataStoreType
	DataStoreConfig DataStoreConfig
	Logging         DataStoreType
	LoggingConfig   DataStoreConfig
	MediaPath       string
}{LogoutTimeout: time.Hour}

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

var (
	userTokens  = map[string]authToken{}
	scramStates = map[string]SCRAMState{}

	authInfos            = make(map[string]AuthInfo)
	authDB     *sql.Conn = nil
	authMutex            = sync.RWMutex{}
	nonceMutex           = sync.RWMutex{}
	dataFile   *os.File  = nil
	dataDB     *sql.Conn = nil
	dataMutex            = sync.RWMutex{}

	templates *template.Template
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalln(err)
		}
	}()
	initConfig()
	configClose, err := configLogging()
	defer func(err error) {
		if err != nil {
			_, _ = os.Stderr.WriteString("Error: closing config writer: " + err.Error())
		}
	}(configClose())
	if err != nil {
		log.Fatalln("Error: could not initialize logging: " + err.Error())
	}
	authClose, err := initAuth()
	defer func(err error) {
		if err != nil {
			log.Println("Error: closing authentication source: " + err.Error())
		}
	}(authClose())
	if err != nil {
		log.Fatalln("Error: could not initialize authentication" + err.Error())
	}
	dataClose, err := initDataStore()
	defer func(err error) {
		if err != nil {
			log.Println("Error: closing data store: " + err.Error())
		}
	}(dataClose())
	if err != nil {
		log.Fatalln("Error: could not initialize data store: " + err.Error())
	}

	if strings.TrimSpace(Config.MediaPath) == "" {
		Config.MediaPath, err = filepath.Abs("./media/")
		if err != nil {
			log.Fatalln("Error: could not make media path absolute: " + err.Error())
		}
		err = os.Mkdir(Config.MediaPath, 0766)
		if err != nil && !os.IsExist(err) {
			log.Fatalln("Error: could not create media directory: " + err.Error())
		}
	}
	if _, err := os.ReadDir(Config.MediaPath); err != nil {
		log.Fatalln("Error: can not list contents of " + Config.MediaPath + " : " + err.Error())
	}
	if strings.TrimSpace(Config.Port) == "" {
		Config.Port = "80"
	}
	var ssl = Config.SslCert != "" && Config.SslKey != ""
	if (Config.SslCert != "" || Config.SslKey != "") && !ssl {
		log.Fatalln("Error: ssl cert and key must be set both")
	}
	if Config.BaseUrl == "" {
		if ssl {
			Config.BaseUrl = "https://" + Config.Hostname
		} else {
			Config.BaseUrl = "http://" + Config.Hostname
		}
		if Config.Hostname == "" {
			Config.BaseUrl += "localhost"
		}
	}

	if err := initTemplates(); err != nil {
		log.Fatalln("Error: could not initialize templates: " + err.Error())
	}

	mux := http.NewServeMux()
	mux.HandleFunc(Config.Hostname+"/", defaultHandler)
	mux.HandleFunc("POST "+Config.Hostname+"/auth", authHandler)
	mux.HandleFunc(Config.Hostname+"/logout", logoutHandler)
	mux.HandleFunc("GET "+Config.Hostname+"/upload", uploadGetHandler)
	mux.HandleFunc("POST "+Config.Hostname+"/upload", uploadPutHandler)
	mux.HandleFunc("PUT "+Config.Hostname+"/upload", uploadPutHandler)
	mux.HandleFunc("GET "+Config.Hostname+"/embed/{uuid}", embedHandler)
	mux.HandleFunc("GET "+Config.Hostname+"/content/{uuid}/{file}", contentHandler)
	var fileHandler = http.FileServerFS(os.DirFS(filepath.Join(".", "templates")))
	for _, fileName := range []string{"style.css", "crypto-js.js", "auth.js", "login.js", "spinner.js", "favicon.ico"} {
		mux.Handle("GET "+Config.Hostname+"/"+fileName, fileHandler)
	}

	if Config.Auth == FILE || Config.Auth == DB {
		var ticker = time.NewTicker(time.Minute * 10)

		go func() {
			for currentTime := range ticker.C {
				var expiredEntries = make([]string, 0, len(scramStates))
				for id, state := range scramStates {
					if state.expires.Before(currentTime) {
						expiredEntries = append(expiredEntries, id)
					}
				}
				nonceMutex.Lock()
				for _, id := range expiredEntries {
					delete(scramStates, id)
				}
				nonceMutex.Unlock()
			}
		}()
		defer ticker.Stop()
	}

	var ticker = time.NewTicker(time.Hour / 2)
	go func() {
		for currentTime := range ticker.C {
			var expiredEntries = make([]string, 0, len(userTokens))
			for id, token := range userTokens {
				if token.expires.Before(currentTime) {
					expiredEntries = append(expiredEntries, id)
				}
			}
			authMutex.Lock()
			for _, id := range expiredEntries {
				delete(userTokens, id)
			}
			authMutex.Unlock()
		}
	}()
	defer ticker.Stop()

	if ssl {
		err = http.ListenAndServeTLS(Config.Host+":"+Config.Port, Config.SslCert, Config.SslKey, mux)
	} else {
		err = http.ListenAndServe(Config.Host+":"+Config.Port, mux)
	}
	log.Fatalln(err)
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		notFoundHandler(w, r)
		return
	}
	if Config.Auth == NONE {
		http.Redirect(w, r, "./upload", http.StatusFound)
		return
	}
	cookie, err := r.Cookie("session")
	if err != nil {
		goto loggedOut
	}
	if !tryLockingWithTimeout(authMutex.TryRLock, time.Second*10) {
		goto loggedOut
	}
	if token, ok := userTokens[cookie.Value]; ok && token.expires.After(time.Now()) {
		authMutex.RUnlock()
		http.Redirect(w, r, "./upload", http.StatusFound)
		return
	}
	authMutex.RUnlock()
loggedOut:
	if err := templates.ExecuteTemplate(w, "index", nil); err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if Config.Auth == NONE {
		http.Redirect(w, r, "./upload", http.StatusFound)
		return
	}
	method, rest := splitFirst(r.Header.Get("Authorization"), ' ')
	if method != "" {
		method = strings.ToLower(method)
		if (Config.Auth == SIMPLE || Config.Auth == EXTERNAL) && method == "basic" {
			var buffer = make([]byte, 255)
			var data, _ = splitFirst(rest, ' ')
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
				errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("could not decode data: %s", err.Error())})
				return
			}
			username, password := splitFirst(string(append(buffer, decoded[:count]...)), ':')
			if ok, err := simpleLogin(username, password); err != nil {
				errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("could not load login: %s", err.Error())})
				return
			} else if ok {
				_, _, err = createTokenAndAddCookie(username, w)
				if err != nil {
					errorHandler(w, r, requestError{StatusCode: http.StatusLocked, Message: fmt.Sprintf("could not create sesstion token: %s", err.Error())})
					return
				}
				http.Redirect(w, r, "./upload", http.StatusFound)
				return
			}
		} else if (Config.Auth == FILE || Config.Auth == DB) && method == "scram-sha-256" {
			var id, data64 string
			for parameter, rest := splitFirst(rest, ','); strings.TrimSpace(parameter) != ""; parameter, rest = splitFirst(rest, ',') {
				name, value := parseParameter(parameter)
				switch strings.ToLower(name) {
				case "sid":
					id = value
				case "data":
					data64 = value
				}
			}
			if data64 == "" {
				errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("auth parameter missing: data")})
				return
			}
			data, err := base64.StdEncoding.DecodeString(data64)
			if err != nil {
				errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
				return
			}
			var scramState SCRAMState
			if id != "" {
				if !tryLockingWithTimeout(nonceMutex.TryRLock, time.Second*10) {
					errorHandler(w, r, requestError{StatusCode: http.StatusLocked, Message: "auth data already locked"})
					return
				}
				defer nonceMutex.RUnlock()
				var ok bool
				if scramState, ok = scramStates[id]; !ok {
					failScramAuth(w, r)
					return
				}
				var clientFinalMessageBuilder = strings.Builder{}
				var proof string
			outside:
				for parameter, rest := splitFirst(string(data), ','); strings.TrimSpace(parameter) != ""; parameter, rest = splitFirst(rest, ',') {
					name, value := parseParameter(parameter)
					switch name {
					case "c":
					case "r":
						if value != scramState.clientNonce+scramState.serverNonce {
							errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: "nonce differs expected nonce"})
							return
						}
					case "p":
						if value == "" {
							errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: "proof can not be empty"})
							return
						}
						proof = value
						break outside
					}
					clientFinalMessageBuilder.WriteByte(',')
					clientFinalMessageBuilder.WriteString(parameter)
				}
				if len(proof) == 0 {
					errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: "auth data parameter missing: p"})
					return
				}
				info, ok, err := getAuthInfo(scramState.username)
				if err != nil {
					errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
					return
				}
				if !ok {
					failScramAuth(w, r)
					return
				}
				var saltedPassword = make([]byte, base64.StdEncoding.DecodedLen(len(info.Hash)))
				if _, err := base64.StdEncoding.Decode(saltedPassword, []byte(info.Hash)); err != nil {
					errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
					return
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
					failScramAuth(w, r)
					return
				}

				if _, _, err := createTokenAndAddCookie(scramState.username, w); err != nil {
					errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
					return
				}

				hashBuilder = hmac.New(sha256.New, saltedPassword)
				hashBuilder.Write([]byte("Server Key"))
				hashBuilder = hmac.New(sha256.New, hashBuilder.Sum(nil))
				hashBuilder.Write(authMessage)
				w.Header().Set("Authentication-Info", fmt.Sprintf("sid=%s,data=%s", id, base64.StdEncoding.EncodeToString([]byte("v="+base64.StdEncoding.EncodeToString(hashBuilder.Sum(nil))))))
				http.Redirect(w, r, "./upload", http.StatusFound)
				return
			} else {
				parameter, rest := splitFirst(string(data), ',')
				if parameter != "n" {
					errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("invalid channel binding flag: %s", parameter)})
					return
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
							errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: "name cannot be empty"})
							return
						}
						salt, iterations, validUser, err = getSaltAndIterations(value)
						if err != nil {
							errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("an error occurred retrieving salt and iteration count: %s", err.Error())})
							return
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
							errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: "nonce cannot be empty"})
							return
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
					errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("auth data parameter missing: %s", missing[1:])})
					return
				}
				if validUser {
					scramState.clientFirstMessageBare = data
					if !tryLockingWithTimeout(nonceMutex.TryLock, time.Second*10) {
						errorHandler(w, r, requestError{StatusCode: http.StatusLocked, Message: "auth data already locked"})
						return
					}
					scramStates[id] = scramState
					nonceMutex.Unlock()
				}
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("SCRAM-SHA-256 sid=%s,data=%s", id, base64.StdEncoding.EncodeToString([]byte(firstServerMessage(scramState.clientNonce+scramState.serverNonce, salt, iterations)))))
				errorHandler(w, r, requestError{StatusCode: http.StatusUnauthorized})
				return
			}
		}
	}
	switch Config.Auth {
	case SIMPLE:
		fallthrough
	case EXTERNAL:
		w.Header().Set("WWW-Authenticate", "BASIC realm=\"\"")
		errorHandler(w, r, requestError{StatusCode: http.StatusUnauthorized})
	case FILE:
		fallthrough
	case DB:
		failScramAuth(w, r)
	case INVALID:
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: "invalid auth type configured"})
	default:
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("unknown auth type configured: %s", Config.Auth)})
	}
}

func failScramAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "SCRAM-SHA-256 realm=\"\"")
	errorHandler(w, r, requestError{StatusCode: http.StatusUnauthorized})
}

func firstServerMessage(nonce, salt string, iterations int) string {
	return fmt.Sprintf("r=%s,s=%s,i=%d", nonce, salt, iterations)
}

func createTokenAndAddCookie(user string, w http.ResponseWriter) (id string, token authToken, err error) {
	var buffer = make([]byte, 32)
	_, _ = rand.Read(buffer)
	id = hex.EncodeToString(buffer)
	token = authToken{
		user:    user,
		expires: time.Now().Add(Config.LogoutTimeout),
	}
	if !tryLockingWithTimeout(authMutex.TryLock, time.Second*10) {
		err = errors.New("auth data already locked")
		return
	}
	userTokens[id] = token
	authMutex.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    id,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  token.expires,
	})
	return
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if !tryLockingWithTimeout(authMutex.TryLock, time.Second*10) {
		errorHandler(w, r, requestError{StatusCode: http.StatusLocked, Message: "auth data already locked"})
		return
	}
	defer authMutex.Unlock()
	_, ok := userTokens[cookie.Value]
	if ok {
		delete(userTokens, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func checkAndRefreshToken(w http.ResponseWriter, r *http.Request) (bool, string, error) {
	if Config.Auth == NONE {
		return true, "anonymous", nil
	}
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return false, "", nil
	}
	if !tryLockingWithTimeout(authMutex.TryLock, time.Second*10) {
		return false, "", errors.New("auth data already locked")
	}
	defer authMutex.Unlock()
	token, ok := userTokens[cookie.Value]
	if !ok || token.expires.Before(time.Now()) {
		if ok {
			delete(userTokens, cookie.Value)
		}
		cookie.Value = ""
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
		return false, "", nil
	}
	token.expires = time.Now().Add(Config.LogoutTimeout)
	var username = token.user
	cookie.MaxAge = 60 * 60
	http.SetCookie(w, cookie)
	return true, username, nil
}

func uploadGetHandler(w http.ResponseWriter, r *http.Request) {
	if ok, _, err := checkAndRefreshToken(w, r); err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	} else if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := templates.ExecuteTemplate(w, "upload", nil); err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
	}
}

type MetaData struct {
	Username string
	MimeType string
	Width    int
	Height   int
}

func uploadPutHandler(w http.ResponseWriter, r *http.Request) {
	ok, username, err := checkAndRefreshToken(w, r)
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	} else if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	contentUUID, err := uuid.NewV7()
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	}
	//1GB
	if err := r.ParseMultipartForm(1073741824); err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	var width = r.Form.Get("width")
	var height = r.Form.Get("height")
	var metaData = MetaData{Username: username}
	metaData.Width, err = strconv.Atoi(width)
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	metaData.Height, err = strconv.Atoi(height)
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	uploadFile, header, err := r.FormFile("video")
	defer func(uploadFile multipart.File) {
		err := uploadFile.Close()
		if err != nil {
			log.Println("Error: closing uploaded video: " + err.Error())
		}
	}(uploadFile)
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	switch header.Header.Get("Content-Type") {
	case "video/mp4":
	case "video/webm":
	case "video/quicktime":
	default:
		errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: "Content-Type must be video/mp4, video/webm or video/quicktime"})
		return
	}
	if err := os.Mkdir(filepath.Join(Config.MediaPath, contentUUID.String()), 0766); err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	}
	var filename = header.Filename
	if strings.HasPrefix(filename, "thumbnail") {
		filename = "_" + filename
	}
	destFile, err := os.Create(filepath.Join(Config.MediaPath, contentUUID.String(), filename))
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	}
	defer func(destFile *os.File) {
		err := destFile.Close()
		if err != nil {
			log.Println("Error: closing local video: " + err.Error())
		}
	}(destFile)
	if _, err := io.Copy(destFile, uploadFile); err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	}
	metaData.MimeType = header.Header.Get("Content-Type")
	uploadedThumbnail, header, err := r.FormFile("thumbnail")
	if err == nil {
		defer func(uploadedThumbnail multipart.File) {
			err := uploadedThumbnail.Close()
			if err != nil {
				log.Println("Error: closing uploaded thumbnail: " + err.Error())
			}
		}(uploadedThumbnail)
		switch header.Header.Get("Content-Type") {
		case "image/webm", "image/avif", "image/gif", "image/jpeg", "image/png", "image/svg+xml", "image/apng", "image/bmp", "image/x-icon", "image/tiff":
		default:
			errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: "Content-Type must be an image type"})
			return
		}
		thumbnail, err := os.Create(filepath.Join(Config.MediaPath, contentUUID.String(), "thumbnail"+filepath.Ext(header.Filename)))
		if err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
			return
		}
		defer func(thumbnail *os.File) {
			err := thumbnail.Close()
			if err != nil {
				log.Println("Error: closing thumbnail: " + err.Error())
			}
		}(thumbnail)
		if _, err := io.Copy(thumbnail, uploadedThumbnail); err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
			return
		}
	} else if !errors.Is(err, http.ErrMissingFile) {
		errorHandler(w, r, requestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	switch Config.DataStore {
	case SIMPLE:
		metaFile, err := os.Create(filepath.Join(Config.MediaPath, contentUUID.String(), "meta.yml"))
		if err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
			return
		}
		defer func(file *os.File) {
			var err = file.Close()
			if err != nil {
				log.Println("Error: closing metadata file: " + err.Error())
			}
		}(metaFile)
		marshalled, err := yaml.Marshal(metaData)
		if err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
			return
		}
		_, err = metaFile.Write(marshalled)
		if err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
			return
		}
	case FILE:
		marshalled, err := json.Marshal(metaData)
		if err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
			return
		}
		var buffer = slices.Concat([]byte(contentUUID.String()), []byte{':'}, marshalled, []byte{'\n'})
		if !tryLockingWithTimeout(dataMutex.TryLock, time.Second*5) {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: "Login Data locked"})
			return
		}
		_, err = dataFile.Write(buffer)
		dataMutex.Unlock()
		if err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
			return
		}
	case DB:
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := dataDB.ExecContext(ctx, "INSERT INTO Contents(Uuid, Username, Mimetype, Width, Height) VALUES (?,?,?,?,?,?)", contentUUID.String(), metaData.Username, metaData.MimeType, metaData.Width, metaData.Height)
		if err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
			return
		}
	case EXTERNAL:
		cmd := exec.Command(Config.DataStoreConfig.ShellCommand, contentUUID.String(), metaData.Username, metaData.MimeType, strconv.Itoa(metaData.Width), strconv.Itoa(metaData.Height))
		if err := cmd.Run(); err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
			return
		}
	}
	http.Redirect(w, r, "./embed/"+contentUUID.String(), http.StatusFound)
}

func embedHandler(w http.ResponseWriter, r *http.Request) {
	var contentUuid = r.PathValue("uuid")
	if strings.TrimSpace(contentUuid) == "" || strings.ContainsAny(contentUuid, "./\\") {
		notFoundHandler(w, r)
		return
	}
	metaData, err := getMetaData(contentUuid)
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	}
	var arguments = struct {
		Id            string
		Title         string
		MimeType      string
		Width, Height int
		Host          string
	}{
		Id:       contentUuid,
		MimeType: metaData.MimeType,
		Width:    metaData.Width,
		Height:   metaData.Height,
		Host:     Config.BaseUrl,
	}
	filesInfos, err := os.ReadDir(filepath.Join(Config.MediaPath, contentUuid))
	if err != nil {
		notFoundHandler(w, r)
	}
	for _, fileInfo := range filesInfos {
		if !fileInfo.IsDir() && !strings.HasPrefix(fileInfo.Name(), "thumbnail") && fileInfo.Name() != "meta.yml" {
			arguments.Title = fileInfo.Name()
		}
	}
	if err := templates.ExecuteTemplate(w, "embed", arguments); err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
	}
}

func contentHandler(w http.ResponseWriter, r *http.Request) {
	var contentUuid = r.PathValue("uuid")
	var fileType = r.PathValue("file")
	if strings.TrimSpace(contentUuid) == "" || strings.ContainsAny(contentUuid, ".") || (fileType != "media" && fileType != "thumbnail") {
		notFoundHandler(w, r)
		return
	}
	filesInfos, err := os.ReadDir(filepath.Join(Config.MediaPath, contentUuid))
	if os.IsNotExist(err) {
		notFoundHandler(w, r)
		return
	}
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	}
	var filePath, mimeType string
	switch fileType {
	case "media":
		metaData, err := getMetaData(contentUuid)
		if err != nil {
			errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
			return
		}
		mimeType = metaData.MimeType
		for _, fileInfo := range filesInfos {
			if !fileInfo.IsDir() && !strings.HasPrefix(fileInfo.Name(), "thumbnail") && fileInfo.Name() != "meta.yml" {
				filePath = filepath.Join(Config.MediaPath, contentUuid, fileInfo.Name())
			}
		}
	case "thumbnail":
		for _, fileInfo := range filesInfos {
			if !fileInfo.IsDir() && strings.HasPrefix(fileInfo.Name(), "thumbnail") {
				switch filepath.Ext(fileInfo.Name()) {
				case ".jpg", ".jpeg":
					mimeType = "image/jpeg"
				case ".png":
					mimeType = "image/png"
				case ".gif":
					mimeType = "image/gif"
				case ".webm":
					mimeType = "image/webm"
				case ".avif":
					mimeType = "image/avif"
				case ".svg":
					mimeType = "image/svg+xml"
				case ".apng":
					mimeType = "image/apng"
				case ".bmp":
					mimeType = "image/bmp"
				case ".ico", ".cur":
					mimeType = "image/x-icon"
				case "tif", "tiff":
					mimeType = "image/tiff"
				default:
					errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("file type not supported: %s", fileInfo.Name())})
					return
				}
				filePath = filepath.Join(Config.MediaPath, contentUuid, fileInfo.Name())
			}
		}
		if filePath == "" {
			filePath, err = filepath.Abs("./template/thumbnail.svg")
			if err != nil {
				errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: "could not make auth path absolute: " + err.Error()})
				return
			}
		}
	}
	file, err := os.Open(filePath)
	if os.IsNotExist(err) {
		notFoundHandler(w, r)
		return
	}
	if err != nil {
		errorHandler(w, r, requestError{StatusCode: http.StatusInternalServerError, Message: err.Error()})
		return
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			log.Println("could not close file: " + err.Error())
		}
	}(file)
	w.Header().Set("Content-Type", mimeType)
	http.ServeContent(w, r, filepath.Base(filePath), time.Now(), file)
}

type requestError struct {
	StatusCode int
	Message    string
}

func (re requestError) StatusText() string {
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

func errorHandler(w http.ResponseWriter, _ *http.Request, requestError requestError) {
	w.WriteHeader(requestError.StatusCode)
	if err := templates.ExecuteTemplate(w, "error", requestError); err != nil {
		var msg = "Error: could not execute error template: " + err.Error()
		log.Println(msg)
		w.WriteHeader(requestError.StatusCode)
		_, _ = w.Write([]byte(msg))
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	errorHandler(w, r, requestError{
		StatusCode: http.StatusNotFound,
		Message:    "Not Found",
	})
}
