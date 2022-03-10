package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// EncryptedBody is the JSON body sent to the /submissions endpoint from FormSG.
type EncryptedBody struct {
	Data struct {
		FormID                 string            `json:"formId"`
		SubmissionID           string            `json:"submissionId"`
		EncryptedContent       string            `json:"encryptedContent"`
		Version                int               `json:"version"`
		Created                time.Time         `json:"created"`
		AttachmentDownloadUrls map[string]string `json:"attachmentDownloadUrls"`
	} `json:"data"`
}

// DecryptedBody
type DecryptedBody struct {
	Data struct {
		FormID           string    `json:"formId"`
		SubmissionID     string    `json:"submissionId"`
		DecryptedContent []Field   `json:"decryptedContent"`
		Version          int       `json:"version"`
		Created          time.Time `json:"created"`
	} `json:"data"`
}

// Field
type Field struct {
	ID        string `json:"_id"`
	Answer    string `json:"answer"`
	FieldType string `json:"fieldType"`
	Question  string `json:"question"`
}

type Attachment struct {
	EncryptedFile struct {
		SubmissionPublicKey string `json:"submissionPublicKey"`
		Nonce               string `json:"nonce"`
		Binary              string `json:"binary"`
	} `json:"encryptedFile"`
}

func Decrypt(encryptedBody EncryptedBody) (*DecryptedBody, error) {
	// Split the encrypted content into the submission public key, nonce, and ciphertext.
	splits := strings.Split(encryptedBody.Data.EncryptedContent, ";")
	submissionPublicKey, _ := base64.StdEncoding.DecodeString(splits[0])
	nonceEncrypted := splits[1]

	// Split the nonce into the nonce and encrypted.
	splits = strings.Split(nonceEncrypted, ":")
	nonce, _ := base64.StdEncoding.DecodeString(splits[0])
	encrypted, _ := base64.StdEncoding.DecodeString(splits[1])
	formPrivateKey, _ := base64.StdEncoding.DecodeString(os.Getenv("FORM_SECRET_KEY"))

	// convert the nonce to a 24 byte slice
	var nonceBytes [24]byte
	copy(nonceBytes[:], nonce)

	// convert the submission public key to a 32 byte slice
	var submissionPublicKeyBytes [32]byte
	copy(submissionPublicKeyBytes[:], submissionPublicKey)

	// convert the form private key to a 32 byte slice
	var formPrivateKeyBytes [32]byte
	copy(formPrivateKeyBytes[:], formPrivateKey)

	// Decrypt the ciphertext.
	decBytes, ok := box.Open(nil, []byte(encrypted), &nonceBytes, &submissionPublicKeyBytes, &formPrivateKeyBytes)
	if !ok {
		return nil, fmt.Errorf("Failed to decrypt content")
	}

	var fields []Field
	err := json.Unmarshal(decBytes, &fields)
	if err != nil {
		return nil, err
	}

	var decryptedBody DecryptedBody
	decryptedBody.Data.FormID = encryptedBody.Data.FormID
	decryptedBody.Data.SubmissionID = encryptedBody.Data.SubmissionID
	decryptedBody.Data.DecryptedContent = fields
	decryptedBody.Data.Version = encryptedBody.Data.Version
	decryptedBody.Data.Created = encryptedBody.Data.Created

	return &decryptedBody, nil
}

func DownloadAttachment(url string) ([]byte, error) {
	// download attachment using golang http client
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var attachment Attachment
	err = json.Unmarshal(body, &attachment)
	if err != nil {
		return nil, err
	}

	nonce, _ := base64.StdEncoding.DecodeString(attachment.EncryptedFile.Nonce)
	submissionPublicKey, _ := base64.StdEncoding.DecodeString(attachment.EncryptedFile.SubmissionPublicKey)
	formPrivateKey, _ := base64.StdEncoding.DecodeString(os.Getenv("FORM_SECRET_KEY"))
	binary, _ := base64.StdEncoding.DecodeString(attachment.EncryptedFile.Binary)

	var nonceBytes [24]byte
	copy(nonceBytes[:], nonce)

	var submissionPublicKeyBytes [32]byte
	copy(submissionPublicKeyBytes[:], submissionPublicKey)

	var formPrivateKeyBytes [32]byte
	copy(formPrivateKeyBytes[:], formPrivateKey)

	// decrypt attachment
	decBytes, ok := box.Open(nil, binary, &nonceBytes, &submissionPublicKeyBytes, &formPrivateKeyBytes)
	if !ok {
		return nil, fmt.Errorf("decrypt attachment failed")
	}

	return decBytes, nil
}
