package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/js"
)

func main() {
	fileNames, err := os.ReadDir("./static")
	if err != nil {
		log.Fatalln(err)
	}
	minifier := minify.New()
	minifier.AddFunc("text/css", css.Minify)
	minifier.AddFunc("application/javascript", js.Minify)
	for _, fileName := range fileNames {
		if fileName.IsDir() {
			continue
		}
		var mediaType string
		switch filepath.Ext(fileName.Name()) {
		case ".css":
			mediaType = "text/css"
		case ".js":
			mediaType = "application/javascript"
		default:
			continue
		}
		file, err := os.Open(filepath.Join(".", "static", fileName.Name()))
		if err != nil {
			log.Println(err)
			continue
		}
		destFile, err := os.OpenFile(filepath.Join(".", "templates", fileName.Name()), os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0644)
		if err != nil {
			_ = file.Close()
			log.Println(err)
			continue
		}
		if err := minifier.Minify(mediaType, destFile, file); err != nil {
			_ = file.Close()
			_ = destFile.Close()
			log.Println(err)
			continue
		}
		_ = file.Close()
		if err := destFile.Close(); err != nil {
			log.Println(err)
		}
	}
}
