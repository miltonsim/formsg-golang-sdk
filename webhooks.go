package webhooks

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Header is the header(X-FormSG-Signature) of the request
type Header struct {
	t  string
	s  string
	f  string
	v1 string
}

// Parsing Header
// header string format is like:
// t=1582558358788,s=5e53ec96b10ee1010e00380b,f=5e4b8e3d1f61f00036c9937d,v1=rUAgQ9krNZspCrQtfSvRfjME6Nq4+I80apGXnCsNrwPbcq44SBNglWtA1MkpC/VhWtDeJfuV89uV2Aqi42UQBA==
func parseHeader(header string) (Header, error) {
	splits := strings.Split(header, ",")
	if len(splits) != 4 {
		return Header{}, fmt.Errorf("header format is invalid")
	}

	var h Header
	for _, s := range splits {
		if strings.HasPrefix(s, "t=") {
			h.t = s[2:]
		} else if strings.HasPrefix(s, "s=") {
			h.s = s[2:]
		} else if strings.HasPrefix(s, "f=") {
			h.f = s[2:]
		} else if strings.HasPrefix(s, "v1=") {
			h.v1 = s[3:]
		} else {
			return Header{}, fmt.Errorf("header format is invalid")
		}
	}

	return h, nil
}

func Authenticate(header string) error {
	h, err := parseHeader(header)

	if err != nil {
		return err
	}

	if h.t == "" || h.s == "" || h.f == "" || h.v1 == "" {
		return fmt.Errorf("X-FormSG-Signature header format is invalid")
	}

	baseString := fmt.Sprintf("%s.%s.%s.%s", os.Getenv("FORM_POST_URI"), h.s, h.f, h.t)

	formPublicKeyBytes, err := base64.StdEncoding.DecodeString(os.Getenv("FORM_PUBLIC_KEY"))
	if err != nil {
		return err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(h.v1)
	if err != nil {
		return err
	}

	if !ed25519.Verify(formPublicKeyBytes, []byte(baseString), signatureBytes) {
		return errors.New("X-FormSG-Signature header is invalid")
	}

	// change string to int64
	i, err := strconv.ParseInt(h.t, 10, 64)
	if err != nil {
		return err
	}

	epoch := time.Unix(0, i*int64(time.Millisecond))
	now := time.Now()

	// Check the epoch submitted is recent and valid.
	//  Prevents against replay attacks. Allows for negative time interval(-300000 milli sec)
	//  in case of clock drift between Form servers and recipient server.
	if epoch.Add(time.Duration(300000) * time.Millisecond).Before(now) {
		return errors.New("signature is not recent")
	}
	return nil
}
