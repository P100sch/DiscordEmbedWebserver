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

//go:embed templates
var embeddedTemplates embed.FS

func initTemplates() error {
	_, err := os.ReadDir(filepath.Join(".", "templates"))
	if os.IsNotExist(err) {
		if err = initTemplateFolder(); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}

	templates = template.New("templates")
	if err := loadTemplate(templates, "./templates/meta.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./templates/header.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./templates/footer.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./templates/error.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./templates/index.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./templates/upload.gohtml"); err != nil {
		return err
	}
	if err := loadTemplate(templates, "./templates/embed.gohtml"); err != nil {
		return err
	}
	return nil
}

func initTemplateFolder() error {
	fileNames, err := embeddedTemplates.ReadDir("templates")
	if err != nil {
		return err
	}
	err = os.Mkdir(filepath.Join(".", "templates"), 0766)
	if err != nil {
		return err
	}
	for _, filename := range fileNames {
		embeddedFile, err := embeddedTemplates.Open(path.Join("templates", filename.Name()))
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
		_, err = baseTemplate.ParseFS(embeddedTemplates, name)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}
