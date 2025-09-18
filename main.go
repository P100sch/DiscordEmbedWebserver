package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

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

var (
	userTokens  = map[string]authToken{}
	scramStates = map[string]SCRAMState{}

	authInfos            = make(map[string]AuthInfo)
	authDB     *sql.Conn = nil
	authMutex            = sync.RWMutex{}
	nonceMutex           = sync.RWMutex{}

	dataFile  *os.File  = nil
	dataDB    *sql.Conn = nil
	dataMutex           = sync.RWMutex{}

	templates *template.Template
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalln(err)
		}
	}()

	defer func(close func() error) {
		if err := close(); err != nil {
			log.Fatalln(err)
		}
	}(initialize())

	mux := http.NewServeMux()
	mux.HandleFunc(Config.Hostname+"/", makeGzipHandlerFunc(defaultHandler))
	mux.HandleFunc("POST "+Config.Hostname+"/auth", authHandler)
	mux.HandleFunc(Config.Hostname+"/logout", logoutHandler)
	mux.HandleFunc("GET "+Config.Hostname+"/upload", makeGzipHandlerFunc(uploadGetHandler))
	mux.HandleFunc("POST "+Config.Hostname+"/upload", uploadPutHandler)
	mux.HandleFunc("PUT "+Config.Hostname+"/upload", uploadPutHandler)
	mux.HandleFunc("GET "+Config.Hostname+"/embed/{uuid}", makeGzipHandlerFunc(embedHandler))
	mux.HandleFunc("GET "+Config.Hostname+"/content/{uuid}/{file}", contentHandler)
	var staticResourcePath, err = filepath.Abs("./resources/static")
	if err != nil {
		log.Fatalln("Error: could not make media path absolute: " + err.Error())
	}
	var fileHandler = http.FileServerFS(os.DirFS(staticResourcePath))
	if files, err := os.ReadDir(staticResourcePath); err == nil {
		for _, file := range files {
			mux.Handle("GET "+Config.Hostname+"/"+file.Name(), fileHandler)
		}
	} else if !os.IsNotExist(err) {
		log.Fatalln(err)
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

	if Config.SslCert != "" && Config.SslKey != "" {
		err = http.ListenAndServeTLS(Config.Host+":"+Config.Port, Config.SslCert, Config.SslKey, mux)
	} else {
		err = http.ListenAndServe(Config.Host+":"+Config.Port, mux)
	}
	log.Fatalln(err)
}
