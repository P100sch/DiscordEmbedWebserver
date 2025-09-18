package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

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
		errorHandler(w, r, internalServerErrorWrapper(err))
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
			if ok, username, requestError := simpleLogin(rest); requestError != noRequestError {
				errorHandler(w, r, requestError)
				return
			} else if ok {
				_, _, err := createTokenAndAddCookie(username, w)
				if err != nil {
					errorHandler(w, r, RequestError{StatusCode: http.StatusLocked, Message: fmt.Sprintf("could not create sesstion token: %s", err.Error())})
					return
				}
				http.Redirect(w, r, "./upload", http.StatusFound)
				return
			}
		} else if (Config.Auth == FILE || Config.Auth == DB) && method == "scram-sha-256" {
			ok, id, response, username, requestError := scramLogin(rest)
			if requestError != noRequestError {
				errorHandler(w, r, requestError)
				return
			}
			switch ok {
			case TRUE:
				if _, _, err := createTokenAndAddCookie(username, w); err != nil {
					errorHandler(w, r, internalServerErrorWrapper(err))
					return
				}
				w.Header().Set("Authentication-Info", fmt.Sprintf("sid=%s,data=%s", id, base64.StdEncoding.EncodeToString([]byte(response))))
				http.Redirect(w, r, "./upload", http.StatusFound)

				if tryLockingWithTimeout(nonceMutex.TryLock, time.Second*10) {
					delete(scramStates, id)
				}
				return
			case FALSE:
				failScramAuth(w, r)
				return
			case CONTINUE:
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("SCRAM-SHA-256 sid=%s,data=%s", id, base64.StdEncoding.EncodeToString([]byte(response))))
				errorHandler(w, r, RequestError{StatusCode: http.StatusUnauthorized})
				return
			}
		}
	}
	switch Config.Auth {
	case SIMPLE:
		fallthrough
	case EXTERNAL:
		w.Header().Set("WWW-Authenticate", "BASIC realm=\"\"")
		errorHandler(w, r, RequestError{StatusCode: http.StatusUnauthorized})
	case FILE:
		fallthrough
	case DB:
		failScramAuth(w, r)
	case INVALID:
		errorHandler(w, r, RequestError{StatusCode: http.StatusInternalServerError, Message: "invalid auth type configured"})
	default:
		errorHandler(w, r, RequestError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("unknown auth type configured: %s", Config.Auth)})
	}
}

func failScramAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "SCRAM-SHA-256 realm=\"\"")
	errorHandler(w, r, RequestError{StatusCode: http.StatusUnauthorized})
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
		errorHandler(w, r, RequestError{StatusCode: http.StatusLocked, Message: "auth data already locked"})
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
		errorHandler(w, r, internalServerErrorWrapper(err))
		return
	} else if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := templates.ExecuteTemplate(w, "upload", nil); err != nil {
		errorHandler(w, r, internalServerErrorWrapper(err))
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
		errorHandler(w, r, internalServerErrorWrapper(err))
		return
	} else if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	contentUUID, err := uuid.NewV7()
	if err != nil {
		errorHandler(w, r, internalServerErrorWrapper(err))
		return
	}
	//1GB
	if err := r.ParseMultipartForm(1073741824); err != nil {
		errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	var width = r.Form.Get("width")
	var height = r.Form.Get("height")
	var metaData = MetaData{Username: username}
	metaData.Width, err = strconv.Atoi(width)
	if err != nil {
		errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: "bad width value: " + err.Error()})
		return
	}
	metaData.Height, err = strconv.Atoi(height)
	if err != nil {
		errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: "bad height value: " + err.Error()})
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
		errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	switch header.Header.Get("Content-Type") {
	case "video/mp4":
	case "video/webm":
	case "video/quicktime":
	default:
		errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: "Content-Type must be video/mp4, video/webm or video/quicktime"})
		return
	}
	if err := os.Mkdir(filepath.Join(Config.MediaPath, contentUUID.String()), 0766); err != nil {
		errorHandler(w, r, internalServerErrorWrapper(err))
		return
	}
	var filename = header.Filename
	if strings.HasPrefix(filename, "thumbnail") {
		filename = "_" + filename
	}
	destFile, err := os.Create(filepath.Join(Config.MediaPath, contentUUID.String(), filename))
	if err != nil {
		errorHandler(w, r, internalServerErrorWrapper(err))
		return
	}
	defer func(destFile *os.File) {
		err := destFile.Close()
		if err != nil {
			log.Println("Error: closing local video: " + err.Error())
		}
	}(destFile)
	if _, err := io.Copy(destFile, uploadFile); err != nil {
		errorHandler(w, r, internalServerErrorWrapper(err))
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
		//goland:noinspection SpellCheckingInspection
		case "image/webm", "image/avif", "image/gif", "image/jpeg", "image/png", "image/svg+xml", "image/apng", "image/bmp", "image/x-icon", "image/tiff":
		default:
			errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: "Content-Type must be an image type"})
			return
		}
		thumbnail, err := os.Create(filepath.Join(Config.MediaPath, contentUUID.String(), "thumbnail"+filepath.Ext(header.Filename)))
		if err != nil {
			errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
			return
		}
		defer func(thumbnail *os.File) {
			err := thumbnail.Close()
			if err != nil {
				log.Println("Error: closing thumbnail: " + err.Error())
			}
		}(thumbnail)
		if _, err := io.Copy(thumbnail, uploadedThumbnail); err != nil {
			errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
			return
		}
	} else if !errors.Is(err, http.ErrMissingFile) {
		errorHandler(w, r, RequestError{StatusCode: http.StatusBadRequest, Message: err.Error()})
		return
	}
	if requestError := setMetaData(contentUUID.String(), metaData); requestError != noRequestError {
		errorHandler(w, r, requestError)
		return
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
		errorHandler(w, r, internalServerErrorWrapper(err))
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
		errorHandler(w, r, internalServerErrorWrapper(err))
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
		errorHandler(w, r, internalServerErrorWrapper(err))
		return
	}
	var filePath, mimeType string
	switch fileType {
	case "media":
		metaData, err := getMetaData(contentUuid)
		if err != nil {
			errorHandler(w, r, internalServerErrorWrapper(err))
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
					errorHandler(w, r, RequestError{StatusCode: http.StatusInternalServerError, Message: fmt.Sprintf("file type not supported: %s", fileInfo.Name())})
					return
				}
				filePath = filepath.Join(Config.MediaPath, contentUuid, fileInfo.Name())
			}
		}
		if filePath == "" {
			filePath, err = filepath.Abs("./resources/template/thumbnail.svg")
			if err != nil {
				errorHandler(w, r, RequestError{StatusCode: http.StatusInternalServerError, Message: "could not make auth path absolute: " + err.Error()})
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
		errorHandler(w, r, internalServerErrorWrapper(err))
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

func errorHandler(w http.ResponseWriter, _ *http.Request, requestError RequestError) {
	w.WriteHeader(requestError.StatusCode)
	if err := templates.ExecuteTemplate(w, "error", requestError); err != nil {
		var msg = "Error: could not execute error template: " + err.Error()
		log.Println(msg)
		w.WriteHeader(requestError.StatusCode)
		_, _ = w.Write([]byte(msg))
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	errorHandler(w, r, RequestError{
		StatusCode: http.StatusNotFound,
		Message:    "Not Found",
	})
}
