package main

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	_ "github.com/mattn/go-sqlite3"
)

func dummyClose() error { return nil }

func getFile(path string, mode int) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|mode, 0666)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func getDB(driver, connectionString string) (*sql.Conn, func() error, error) {
	db, err := sql.Open(driver, connectionString)
	if err != nil {
		return nil, dummyClose, err
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		_ = db.Close()
		return nil, dummyClose, err
	}
	return conn, func() error {
		err := conn.Close()
		if err != nil {
			return err
		}
		return db.Close()
	}, nil
}

func configLogging() (func() error, error) {
	const testMessage = "Info: Application started"
	switch Config.Logging {
	case NONE:
		log.SetOutput(io.Discard)
		return dummyClose, nil
	case SIMPLE:
		log.SetOutput(os.Stdout)
		return dummyClose, nil
	case FILE:
		if strings.TrimSpace(Config.LoggingConfig.FilePath) == "" {
			var err error
			Config.LoggingConfig.FilePath, err = filepath.Abs("./log.txt")
			if err != nil {
				return dummyClose, errors.New("could not make log path absolute: " + err.Error())
			}
		}
		file, err := getFile(Config.LoggingConfig.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND)
		if err != nil {
			return dummyClose, err
		}
		if _, err := file.WriteString(testMessage + "\n"); err != nil {
			_ = file.Close()
			return dummyClose, err
		}
		log.SetOutput(file)
		return func() error {
			return file.Close()
		}, nil
	case DB:
		var initDB = false
		if strings.TrimSpace(Config.LoggingConfig.DBDriver) == "" && strings.TrimSpace(Config.LoggingConfig.ConnectionString) == "" {
			Config.LoggingConfig.DBDriver = "sqlite3"
			Config.LoggingConfig.ConnectionString = "file:./data.db"
			initDB = true
		}
		conn, closeFunc, err := getDB(Config.LoggingConfig.DBDriver, Config.LoggingConfig.ConnectionString)
		if err != nil {
			return dummyClose, err
		}
		if initDB {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := conn.ExecContext(ctx, "CREATE TABLE If NOT EXISTS Logs(TIMESTAMP TEXT, Message TEXT)"); err != nil {
				_ = closeFunc()
				return dummyClose, err
			}
		}
		writer := &dbWriter{conn}
		if _, err := writer.Write([]byte(testMessage)); err != nil {
			_ = closeFunc()
			return dummyClose, err
		}
		log.SetOutput(writer)
		return closeFunc, nil
	case EXTERNAL:
		writer := shellWriter(Config.LoggingConfig.ShellCommand)
		if _, err := writer.Write([]byte(testMessage)); err != nil {
			return dummyClose, err
		}
		return dummyClose, nil
	default:
		panic(fmt.Sprintf("Error: Invalid logging method: %s\n", Config.Logging))
		return nil, nil
	}
}

func initAuth() (func() error, error) {
	switch Config.Auth {
	case NONE:
		return dummyClose, nil
	case SIMPLE:
		if strings.TrimSpace(Config.AuthConfig.FilePath) == "" {
			var err error
			Config.AuthConfig.FilePath, err = filepath.Abs("./logins.yaml")
			if err != nil {
				return dummyClose, errors.New("could not make auth path absolute: " + err.Error())
			}
		}
		authFile, err := os.ReadFile(Config.AuthConfig.FilePath)
		if err != nil {
			return dummyClose, err
		}
		var simpleAuthInfos = make([]struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		}, 0)
		if yaml.Unmarshal(authFile, &simpleAuthInfos) != nil {
			return dummyClose, err
		}
		authInfos = make(map[string]AuthInfo, len(simpleAuthInfos))
		for _, info := range simpleAuthInfos {
			var hasher = crypto.SHA256.New()
			if _, err := hasher.Write([]byte(info.Password)); err != nil {
				return dummyClose, err
			}
			var builder = strings.Builder{}
			if _, err := base64.NewEncoder(base64.StdEncoding, &builder).Write(hasher.Sum(nil)); err != nil {
				return dummyClose, err
			}
			authInfos[info.Username] = AuthInfo{
				Username:   info.Username,
				Salt:       "",
				Hash:       builder.String(),
				Iterations: 0,
			}
		}
		return dummyClose, nil
	case FILE:
		if strings.TrimSpace(Config.AuthConfig.FilePath) == "" {
			var err error
			Config.AuthConfig.FilePath, err = filepath.Abs("./logins.yaml")
			if err != nil {
				return dummyClose, errors.New("could not make log path absolute: " + err.Error())
			}
		}
		authFile, err := os.ReadFile(Config.AuthConfig.FilePath)
		if err != nil {
			return dummyClose, err
		}
		var infos []AuthInfo
		if err := yaml.Unmarshal(authFile, &infos); err != nil {
			return dummyClose, err
		}
		for _, info := range infos {
			authInfos[info.Username] = info
		}
		return dummyClose, nil
	case DB:
		var initDB = false
		if strings.TrimSpace(Config.DataStoreConfig.DBDriver) == "" && strings.TrimSpace(Config.DataStoreConfig.ConnectionString) == "" {
			Config.DataStoreConfig.DBDriver = "sqlite3"
			Config.DataStoreConfig.ConnectionString = "file:./data.db"
			initDB = true
		}
		conn, closeFunc, err := getDB(Config.AuthConfig.DBDriver, Config.AuthConfig.ConnectionString)
		if err != nil {
			return dummyClose, err
		}
		if initDB {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := conn.ExecContext(ctx, "CREATE TABLE If NOT EXISTS Users(Username TEXT, Salt TEXT, Hash TEXT, Iterations INTEGER)"); err != nil {
				_ = closeFunc()
				return dummyClose, err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if row := conn.QueryRowContext(ctx, "SELECT Salt, Hash, Iterations FROM Users WHERE Username = ?", "TEST"); row.Err() != nil {
			_ = closeFunc()
			return dummyClose, row.Err()
		}
		authDB = conn
		return closeFunc, nil
	case EXTERNAL:
		cmd := exec.Command(Config.AuthConfig.ShellCommand)
		var builder = strings.Builder{}
		cmd.Stdout = &builder
		if err := cmd.Run(); err != nil {
			return dummyClose, err
		}
		var response = strings.ToLower(builder.String())
		if strings.HasPrefix(response, "true") || strings.HasPrefix(response, "false") {
			return dummyClose, errors.New("invalid response from auth command: " + response)
		}
		return dummyClose, nil
	default:
		panic(fmt.Sprintf("Error: Invalid auth method: %s\n", Config.Auth))
		return nil, nil
	}
}

func initDataStore() (func() error, error) {
	switch Config.DataStore {
	case NONE:
		return dummyClose, errors.New("data store method required")
	case SIMPLE:
		return dummyClose, nil
	case FILE:
		if strings.TrimSpace(Config.DataStoreConfig.FilePath) == "" {
			var err error
			Config.DataStoreConfig.FilePath, err = filepath.Abs("./data.yaml")
			if err != nil {
				return dummyClose, errors.New("could not make auth path absolute: " + err.Error())
			}
		}
		file, err := getFile(Config.DataStoreConfig.FilePath, os.O_RDWR|os.O_APPEND)
		if err != nil {
			return dummyClose, err
		}
		dataFile = file
		return file.Close, nil
	case DB:
		var initDB = false
		if strings.TrimSpace(Config.DataStoreConfig.DBDriver) == "" && strings.TrimSpace(Config.DataStoreConfig.ConnectionString) == "" {
			Config.DataStoreConfig.DBDriver = "sqlite3"
			Config.DataStoreConfig.ConnectionString = "file:./data.db"
			initDB = true
		}
		conn, closeFunc, err := getDB(Config.DataStoreConfig.DBDriver, Config.DataStoreConfig.ConnectionString)
		if err != nil {
			return dummyClose, err
		}
		if initDB {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := conn.ExecContext(ctx, "CREATE TABLE If NOT EXISTS Contents(UUID TEXT, Username TEXT, MIMEType TEXT, Width INTEGER, Height INTEGER)"); err != nil {
				_ = closeFunc()
				return dummyClose, err
			}
		}
		dataDB = conn
		return closeFunc, nil
	case EXTERNAL:
		return dummyClose, nil
	default:
		panic(fmt.Sprintf("Error: Invalid data storage method: %s\n", Config.DataStore))
		return nil, nil
	}
}

type dbWriter struct {
	conn *sql.Conn
}

func (w *dbWriter) Write(p []byte) (n int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if result, err := w.conn.ExecContext(ctx, "INSERT INTO Logs(Timestamp,Message) VALUES (?,?)", time.Now(), string(p)); err != nil {
		return 0, err
	} else if num, err := result.RowsAffected(); err != nil {
		return 0, err
	} else if num != 1 {
		return 0, errors.New("can not inserting log message")
	}
	return len(p), nil
}

type shellWriter string

func (s *shellWriter) Write(p []byte) (n int, err error) {
	cmd := exec.Command(fmt.Sprintf(string(*s), string(p)))
	if err := cmd.Run(); err != nil {
		return 0, err
	}
	return len(p), nil
}
