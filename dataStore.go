package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

func getSaltAndIterations(username string) (string, int, bool, error) {
	switch Config.Auth {

	case FILE:
		info, ok := authInfos[username]
		if !ok {
			return "", 0, false, nil
		}
		return info.Salt, info.Iterations, true, nil

	case DB:
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var row = authDB.QueryRowContext(ctx, "SELECT Salt, Iterations FROM Users WHERE Username = ?", username)
		if row.Err() != nil {
			return "", 0, false, row.Err()
		}
		var (
			salt       string
			iterations int
		)
		if err := row.Scan(&salt, &iterations); errors.Is(err, sql.ErrNoRows) {
			return "", 0, false, nil
		} else if err != nil {
			return "", 0, false, err
		}
		return salt, iterations, true, nil

	default:
		return "", 0, false, nil
	}
}

func getAuthInfo(username string) (AuthInfo, bool, error) {
	switch Config.Auth {

	case FILE:
		info, ok := authInfos[username]
		if !ok {
			return AuthInfo{}, false, nil
		}
		return info, true, nil

	case DB:
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var row = authDB.QueryRowContext(ctx, "SELECT Hash, Salt, Iterations FROM Users WHERE Username = ?", username)
		if row.Err() != nil {
			return AuthInfo{}, false, row.Err()
		}
		var info = AuthInfo{Username: username}
		if err := row.Scan(&info.Hash, &info.Salt, &info.Iterations); errors.Is(err, sql.ErrNoRows) {
			return AuthInfo{}, false, nil
		} else if err != nil {
			return AuthInfo{}, false, err
		}
		return info, true, nil

	default:
		return AuthInfo{}, false, nil
	}
}

func validateSimpleLogin(username, password string) (bool, error) {
	switch Config.Auth {

	case SIMPLE:
		info, ok := authInfos[username]
		return ok && info.Hash == password, nil

	case EXTERNAL:
		cmd := exec.Command(Config.AuthConfig.ShellCommand, username, password)
		var builder = strings.Builder{}
		cmd.Stdout = &builder
		if err := cmd.Run(); err != nil {
			return false, err
		}
		var response = strings.ToLower(builder.String())
		if !strings.HasPrefix(response, "true") || !strings.HasPrefix(response, "false") {
			return false, errors.New(response)
		}
		return strings.HasPrefix(response, "true"), nil

	case INVALID:
		return false, errors.New("invalid auth type configured")
	default:
		return false, errors.New("unknown auth type configured")
	}
}

func setMetaData(uuid string, metaData MetaData) RequestError {
	switch Config.DataStore {
	case SIMPLE:
		metaFile, err := os.Create(filepath.Join(Config.MediaPath, uuid, "meta.yml"))
		if err != nil {
			return internalServerErrorWrapper(err)
		}
		defer func(file *os.File) {
			var err = file.Close()
			if err != nil {
				log.Println("Error: closing metadata file: " + err.Error())
			}
		}(metaFile)
		marshalled, err := yaml.Marshal(metaData)
		if err != nil {
			return internalServerErrorWrapper(err)
		}
		_, err = metaFile.Write(marshalled)
		if err != nil {
			return internalServerErrorWrapper(err)
		}
	case FILE:
		marshalled, err := json.Marshal(metaData)
		if err != nil {
			return internalServerErrorWrapper(err)
		}
		var buffer = slices.Concat([]byte(uuid), []byte{':'}, marshalled, []byte{'\n'})
		if !tryLockingWithTimeout(dataMutex.TryLock, time.Second*5) {
			return RequestError{StatusCode: http.StatusInternalServerError, Message: "Login Data locked"}
		}
		_, err = dataFile.Write(buffer)
		dataMutex.Unlock()
		if err != nil {
			return internalServerErrorWrapper(err)
		}
	case DB:
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := dataDB.ExecContext(ctx, "INSERT INTO Contents(Uuid, Username, Mimetype, Width, Height) VALUES (?,?,?,?,?,?)", uuid, metaData.Username, metaData.MimeType, metaData.Width, metaData.Height)
		if err != nil {
			return internalServerErrorWrapper(err)
		}
	case EXTERNAL:
		cmd := exec.Command(Config.DataStoreConfig.ShellCommand, uuid, metaData.Username, metaData.MimeType, strconv.Itoa(metaData.Width), strconv.Itoa(metaData.Height))
		if err := cmd.Run(); err != nil {
			return internalServerErrorWrapper(err)
		}
	}
	return noRequestError
}

func getMetaData(contentUuid string) (MetaData, error) {
	switch Config.DataStore {

	case SIMPLE:
		metaDataFile, err := os.ReadFile(filepath.Join(Config.MediaPath, contentUuid, "meta.yml"))
		if os.IsNotExist(err) {
			return MetaData{}, errors.New("metadata not found")
		}
		if err != nil {
			return MetaData{}, err
		}
		var metaData MetaData
		if err := yaml.Unmarshal(metaDataFile, &metaData); err != nil {
			return metaData, err
		}
		return metaData, nil

	case FILE:
		if !tryLockingWithTimeout(dataMutex.TryRLock, time.Second*5) {
			return MetaData{}, errors.New("metadata locked")
		}
		defer dataMutex.RUnlock()
		if _, err := dataFile.Seek(0, 2); err != nil {
			return MetaData{}, err
		}
		var scanner = bufio.NewScanner(dataFile)
		for scanner.Scan() {
			id, rest := splitFirst(scanner.Text(), ':')
			if id == contentUuid {
				var metaData MetaData
				if err := json.Unmarshal([]byte(rest), &metaData); err != nil {
					return metaData, err
				}
				return metaData, nil
			}
		}
		var err = scanner.Err()
		if err != io.EOF {
			return MetaData{}, err
		}
		return MetaData{}, errors.New("can not find metadata")

	case DB:
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var row = dataDB.QueryRowContext(ctx, "SELECT Mimetype, Username, Width, Height FROM Contents WHERE Uuid = ?", contentUuid)
		if row.Err() != nil {
			return MetaData{}, row.Err()
		}
		var metaData MetaData
		if err := row.Scan(&metaData.MimeType, &metaData.Username, &metaData.Width, &metaData.Height); errors.Is(err, sql.ErrNoRows) {
			return metaData, errors.New("metadata not found")
		} else if err != nil {
			return metaData, err
		}
		return metaData, nil

	case EXTERNAL:
		cmd := exec.Command(Config.DataStoreConfig.ShellCommand, contentUuid)
		var builder = strings.Builder{}
		cmd.Stdout = &builder
		if err := cmd.Run(); err != nil {
			return MetaData{}, err
		}
		var metaData MetaData
		if err := json.Unmarshal([]byte(builder.String()), &metaData); err != nil {
			return MetaData{}, err
		}
		return metaData, nil

	default:
		return MetaData{}, errors.New("invalid data storage method")
	}
}
