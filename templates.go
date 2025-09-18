package main

import (
	"embed"
	"html/template"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
)

//go:embed resources
var embededFiles embed.FS

func initTemplates() error {
	_, err := os.ReadDir(filepath.Join(".", "resources", "templates"))
	if os.IsNotExist(err) {
		if err = initResourceFolder(); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}

	templates = template.New("templates")
	if err := loadTemplate(templates, "./resources/templates/meta.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./resources/templates/header.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./resources/templates/footer.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./resources/templates/error.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./resources/templates/index.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./resources/templates/upload.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./resources/templates/embed.gohtml"); err != nil {
		return err
	}
	return nil
}

func initResourceFolder() error {
	fileNames, err := embededFiles.ReadDir("resources/templates")
	if err != nil {
		return err
	}
	err = os.Mkdir(filepath.Join(".", "templates"), 0766)
	if err != nil {
		return err
	}
	for _, filename := range fileNames {
		embeddedFile, err := embededFiles.Open(path.Join("resources/templates", filename.Name()))
		if err != nil {
			return err
		}
		defer func(file fs.File) {
			err := file.Close()
			if err != nil {
				log.Println("Error: closing embedded template: " + err.Error())
			}
		}(embeddedFile)
		file, err := os.OpenFile(filepath.Join(".", "templates", filename.Name()), os.O_CREATE|os.O_RDWR, 0766)
		defer func(file fs.File) {
			err := file.Close()
			if err != nil {
				log.Println("Error: closing copied template: " + err.Error())
			}
		}(file)
		if err != nil {
			return err
		}
		_, err = io.Copy(file, embeddedFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func loadTemplate(baseTemplate *template.Template, name string) error {
	_, err := baseTemplate.ParseFiles(name)
	if os.IsNotExist(err) {
		_, err = baseTemplate.ParseFS(embededFiles, name)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}
