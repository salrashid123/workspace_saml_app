package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml/samlsp"
)

var ()

const ()

func gethandler(w http.ResponseWriter, r *http.Request) {
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}

	fmt.Fprintf(w, "Token contents, %+v!", sa)
}

func main() {

	rootURL, err := url.Parse("https://localhost.local:5001/saml")
	if err != nil {
		panic(err)
	}

	dat, err := os.ReadFile("GoogleIDPMetadata.xml")
	if err != nil {
		panic(err)
	}
	idpMetadata, err := samlsp.ParseMetadata(dat)
	if err != nil {
		panic(err)
	}

	ke, err := os.ReadFile("certs/spsigner.crt")
	if err != nil {
		panic(err)
	}

	kr, err := os.ReadFile("certs/spsigner.key")
	if err != nil {
		panic(err)
	}
	keyPair, err := tls.X509KeyPair(ke, kr)
	if err != nil {
		panic(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}
	samlSP, err := samlsp.New(samlsp.Options{
		EntityID:          "elevate.cloud.google.com",
		URL:               *rootURL,
		IDPMetadata:       idpMetadata,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		AllowIDPInitiated: false,
	})
	if err != nil {
		panic(err)
	}

	app := http.HandlerFunc(gethandler)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)

	fmt.Println("Starting Server..")
	err = http.ListenAndServeTLS(":5001", "certs/server.crt", "certs/server.key", nil)
	fmt.Printf("Unable to start Server %v", err)

}
