package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func initConfig() {
	configFilepath, err := filepath.Abs("./config.json")
	if err != nil {
		panic("Error: could not make config path absolute: " + err.Error())
	}

	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--config-path=") {
			configFilepath = strings.Trim(strings.TrimPrefix(arg, "--config-path="), "\"")
		}
	}

	if configFileContent, err := os.ReadFile(configFilepath); err == nil {
		var config = struct {
			Host            string
			Port            string
			Hostname        string
			BaseUrl         string
			SslCert         string
			SslKey          string
			LogoutTimeout   string
			Auth            DataStoreType
			AuthConfig      DataStoreConfig
			DataStore       DataStoreType
			DataStoreConfig DataStoreConfig
			Logging         DataStoreType
			LoggingConfig   DataStoreConfig
			MediaPath       string
		}{}
		if err = json.Unmarshal(configFileContent, &config); err != nil {
			panic("Error: " + err.Error())
		}
		Config.Host = config.Host
		Config.Port = config.Port
		Config.Hostname = config.Hostname
		Config.BaseUrl = config.BaseUrl
		Config.SslCert = config.SslCert
		Config.SslKey = config.SslKey
		Config.Auth = config.Auth
		Config.AuthConfig = config.AuthConfig
		Config.DataStore = config.DataStore
		Config.DataStoreConfig = config.DataStoreConfig
		Config.Logging = config.Logging
		Config.LoggingConfig = config.LoggingConfig
		Config.MediaPath = config.MediaPath
		Config.LogoutTimeout = parseDutration(config.LogoutTimeout)
	} else if !os.IsNotExist(err) {
		panic("Error: " + err.Error())
	}

	for _, arg := range os.Args[1:] {
		switch {
		case strings.HasPrefix(arg, "--host="):
			Config.Host = strings.Trim(strings.TrimPrefix(arg, "--host="), "\"")
		case strings.HasPrefix(arg, "--port="):
			Config.Port = strings.Trim(strings.TrimPrefix(arg, "--port="), "\"")
		case strings.HasPrefix(arg, "--hostname="):
			Config.Hostname = strings.Trim(strings.TrimPrefix(arg, "--hostname="), "\"")
		case strings.HasPrefix(arg, "--url="):
			Config.BaseUrl = strings.Trim(strings.TrimPrefix(arg, "--url="), "\"")
		case strings.HasPrefix(arg, "--sslCert="):
			Config.SslCert = strings.Trim(strings.TrimPrefix(arg, "--sslCert="), "\"")
		case strings.HasPrefix(arg, "--sslKey="):
			Config.SslKey = strings.Trim(strings.TrimPrefix(arg, "--sslKey="), "\"")
		case strings.HasPrefix(arg, "--timeout="):
			Config.LogoutTimeout = parseDutration(strings.Trim(strings.TrimPrefix(arg, "--timeout="), "\""))
		case strings.HasPrefix(arg, "--auth="):
			Config.Auth = DataStoreType(strings.Trim(strings.TrimPrefix(arg, "--auth="), "\""))
		case strings.HasPrefix(arg, "--auth-file="):
			Config.AuthConfig.FilePath = strings.Trim(strings.TrimPrefix(arg, "--auth-file="), "\"")
		case strings.HasPrefix(arg, "--auth-DB="):
			Config.AuthConfig.DBDriver = strings.Trim(strings.TrimPrefix(arg, "--auth-DB="), "\"")
		case strings.HasPrefix(arg, "--auth-DB-Con="):
			Config.AuthConfig.ConnectionString = strings.Trim(strings.TrimPrefix(arg, "--auth-DB-Con="), "\"")
		case strings.HasPrefix(arg, "--auth-hook="):
			Config.AuthConfig.ShellCommand = strings.Trim(strings.TrimPrefix(arg, "--data-store-hook="), "\"")
		case strings.HasPrefix(arg, "--data-store="):
			Config.DataStore = DataStoreType(strings.Trim(strings.TrimPrefix(arg, "--data-store="), "\""))
		case strings.HasPrefix(arg, "--data-store-file="):
			Config.DataStoreConfig.FilePath = strings.Trim(strings.TrimPrefix(arg, "--data-store-file="), "\"")
		case strings.HasPrefix(arg, "--data-store-DB="):
			Config.DataStoreConfig.DBDriver = strings.Trim(strings.TrimPrefix(arg, "--data-store-DB="), "\"")
		case strings.HasPrefix(arg, "--data-store-DB-Con="):
			Config.DataStoreConfig.ConnectionString = strings.Trim(strings.TrimPrefix(arg, "--data-store-DB-Con="), "\"")
		case strings.HasPrefix(arg, "--data-store-hook="):
			Config.DataStoreConfig.ShellCommand = strings.Trim(strings.TrimPrefix(arg, "--data-store-hook="), "\"")
		case strings.HasPrefix(arg, "--logging="):
			Config.Logging = DataStoreType(strings.Trim(strings.TrimPrefix(arg, "--logging="), "\""))
		case strings.HasPrefix(arg, "--logging-file="):
			Config.LoggingConfig.FilePath = strings.Trim(strings.TrimPrefix(arg, "--logging-file="), "\"")
		case strings.HasPrefix(arg, "--logging-DB="):
			Config.LoggingConfig.DBDriver = strings.Trim(strings.TrimPrefix(arg, "--logging-DB="), "\"")
		case strings.HasPrefix(arg, "--logging-DB-Con="):
			Config.LoggingConfig.ConnectionString = strings.Trim(strings.TrimPrefix(arg, "--logging-DB-Con="), "\"")
		case strings.HasPrefix(arg, "--logging-hook="):
			Config.LoggingConfig.ShellCommand = strings.Trim(strings.TrimPrefix(arg, "--logging-hook="), "\"")
		case strings.HasPrefix(arg, "--media="):
			Config.MediaPath = strings.Trim(strings.TrimPrefix(arg, "--media="), "\"")
		default:
			log.Fatalf("Error: %s is an invalid argument\n", arg)
		}
	}

	if Config.Logging == INVALID {
		Config.Logging = SIMPLE
	}
	if Config.Auth == INVALID {
		Config.Auth = SIMPLE
	}
	if Config.DataStore == INVALID {
		Config.DataStore = SIMPLE
	}
}

func parseDutration(str string) time.Duration {
	if str == "" {
		return time.Hour
	}
	var duration = time.Second
	var char = str[len(str)-1]
	switch char {
	case 's':
	case 'm':
		duration = time.Minute
	case 'h':
		duration = time.Hour
	case 'd':
		duration = time.Hour * 24
	case 'w':
		duration = time.Hour * 24 * 7
	case 'M':
		duration = time.Hour * 24 * 30
	case 'Y':
		duration = time.Hour * 24 * 365
	case '1', '2', '3', '4', '5', '6', '7', '8', '9', '0':
	default:
		panic(fmt.Sprintf("Error: invalid duration: %c", char))
	}
	switch char {
	case 's', 'm', 'h', 'd', 'w', 'M', 'Y':
		str = str[:len(str)-1]
	}
	number, err := strconv.Atoi(str)
	if err != nil {
		panic(fmt.Sprintf("Error: could not convert logout timeout to number: %s", err.Error()))
	}
	return duration * time.Duration(number)
}
