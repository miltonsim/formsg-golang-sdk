package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/afnexus/formsg-golang-sdk/crypto"
	"github.com/afnexus/formsg-golang-sdk/webhooks"
)

const (
	// Set to true if you need to download and decrypt attachments from submissions
	has_attachments = true
)

// submissions is the handler for the /submissions endpoint.
func submissions(w http.ResponseWriter, r *http.Request) {
	// Set the Content-Type header to application/json
	w.Header().Set("Content-Type", "application/json")

	// Authenticate the request using the public key
	// Please comment the below codes if you are testing in localhost
	err := webhooks.Authenticate(r.Header.Get("X-FormSG-Signature"))
	if err != nil {
		http.Error(w, `{ "message": "Unauthorized" }`, http.StatusUnauthorized)
		return
	}

	var encryptedBody crypto.EncryptedBody
	// Decode the request body
	err = json.NewDecoder(r.Body).Decode(&encryptedBody)
	if err != nil {
		http.Error(w, `{ "message": "Invalid request" }`, http.StatusBadRequest)
		return
	}

	// Decrypt the submission content
	decryptedBody, err := crypto.Decrypt(encryptedBody)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, `{ "message": "decryption fail"}`, http.StatusBadRequest)
		return
	}

	// save the decrypted submission to a file
	file, err := os.Create(fmt.Sprintf("./temp/%s.json", decryptedBody.Data.SubmissionID))
	if err != nil {
		http.Error(w, `{ "message": "file open fail"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	err = json.NewEncoder(file).Encode(decryptedBody)
	if err != nil {
		http.Error(w, `{ "message": "file write fail"}`, http.StatusBadRequest)
		return
	}

	if has_attachments {
		for _, field := range decryptedBody.Data.DecryptedContent {
			if field.FieldType == "attachment" {
				if download_url, ok := encryptedBody.Data.AttachmentDownloadUrls[field.ID]; ok {
					decBytes, err := crypto.DownloadAttachment(download_url)
					if err != nil {
						log.Println(err.Error())
						http.Error(w, `{ "message": "download attachment fail"}`, http.StatusBadRequest)
						return
					}

					// save attachment to file
					file2, err := os.Create(fmt.Sprintf("./temp/%s.%s", field.ID, field.Answer))
					if err != nil {
						log.Panicln(err.Error())
						http.Error(w, `{ "message": "file open fail"}`, http.StatusBadRequest)
						return
					}
					defer file2.Close()

					_, err = file2.Write(decBytes)
					if err != nil {
						log.Panicln(err.Error())
						http.Error(w, `{ "message": "file write fail"}`, http.StatusBadRequest)
						return
					}
				}
			}
		}
	}

	w.Write([]byte("ok"))
}

func main() {
	if os.Getenv("FORM_PUBLIC_KEY") == "" {
		// set default public key
		os.Setenv("FORM_PUBLIC_KEY", "3Tt8VduXsjjd4IrpdCd7BAkdZl/vUCstu9UvTX84FWw=")
	}
	if os.Getenv("FORM_SECRET_KEY") == "" {
		// Your form's secret key downloaded from FormSG upon form creation FORM_SECRET_KEY
		os.Setenv("FORM_SECRET_KEY", "sVKaIEWVnREJxyzSMjYZNaoKrpH4nFKe9685VKFbXA0=")
	}
	if os.Getenv("FORM_POST_URI") == "" {
		// This is where your domain is hosted, and should match
		// the URI supplied to FormSG in the form dashboard
		os.Setenv("FORM_POST_URI", "https://22c8-49-245-33-49.ngrok.io/submissions")
	}

	// Create temp folder to house the content of the decrypted files from FormSG
	_, err := os.Stat("temp")

	if os.IsNotExist(err) {
		log.Println("Folder does not exist.")
		err := os.Mkdir("temp", 0755)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("Folder exist.")
	}

	http.Handle("/temp/", http.StripPrefix("/temp/", http.FileServer(http.Dir("./temp"))))
	http.HandleFunc("/submissions", submissions)
	http.ListenAndServe(":8080", nil)
}
