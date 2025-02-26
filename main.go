package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ge0r/json-sign-test/pkg/signing"
)

const INDENT = "  "

type User struct {
	Name        string   `json:"full_name"`
	Age         int      `json:"age,omitempty"`       // omit the field if the value is zero
	Interests   []string `json:"interests,omitempty"` // omit the field if the value is nil
	Active      bool     `json:"-"`                   // remove this field from the json output
	Verified    bool     // default field name is used
	lastLoginAt string   // unexported (lowercase) fields are not marshaled
}

type SignedUser struct {
	User      User   `json:"user"`
	Signature string `json:"signature,omitempty"`
}

func main() {
	// Define command line flags for signing, marshalling, and verifying
	signFlag := flag.Bool("sign", false, "Sign the user data")
	marshalFlag := flag.Bool("marshal", false, "Marshal the user data to JSON")
	verifyFlag := flag.Bool("verify", false, "Verify the signed user data")
	flag.Parse()

	if *signFlag {
		signUserData()
		return
	}

	if *marshalFlag {
		marshalUserData()
		return
	}

	if *verifyFlag {
		verifyUserData()
		return
	}
}

func marshalUserData() {
	var interests = []string{"golang", "python", "javascript"}

	var user = User{
		Name:        "Bob",
		Age:         59,
		Interests:   interests,
		Active:      true,
		Verified:    false,
		lastLoginAt: "today",
	}

	u, err := json.MarshalIndent(user, "", INDENT)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("user.json", u, 0644)
	if err != nil {
		log.Fatalf("Failed to write JSON file: %v", err)
	}
}

func signUserData() {
	var interests = []string{"golang", "python", "javascript"}

	var user = User{
		Name:        "Bob",
		Age:         59,
		Interests:   interests,
		Active:      true,
		Verified:    false,
		lastLoginAt: "today",
	}

	u, err := json.MarshalIndent(user, "", INDENT)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("user.json", u, 0644)
	if err != nil {
		log.Fatalf("Failed to write JSON file: %v", err)
	}

	// Generate or load RSA key
	var privateKey *rsa.PrivateKey
	keyFile := "private_key.pem"
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		err = signing.SavePrivateKey(keyFile, privateKey)
		if err != nil {
			log.Fatalf("Failed to save private key: %v", err)
		}
		err = signing.SavePublicKey("public_key.pem", &privateKey.PublicKey)
		if err != nil {
			log.Fatalf("Failed to save public key: %v", err)
		}
	} else {
		privateKey, err = signing.LoadPrivateKey(keyFile)
		if err != nil {
			log.Fatalf("Failed to load private key: %v", err)
		}
	}

	// Sign the JSON data
	sigBytes, err := signing.SignData(privateKey, u)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}

	// Create a new structure with the user data and the signature
	signedUser := SignedUser{
		User:      user,
		Signature: fmt.Sprintf("%x", sigBytes),
	}

	// Marshal the new structure and write it to the file
	signedData, err := json.MarshalIndent(signedUser, "", INDENT)
	if err != nil {
		log.Fatalf("Failed to marshal signed data: %v", err)
	}

	err = os.WriteFile("signed_user.json", signedData, 0644)
	if err != nil {
		log.Fatalf("Failed to write signed JSON file: %v", err)
	}
}

func verifyUserData() {
	// Read the signed JSON file
	signedData, err := os.ReadFile("signed_user.json")
	if err != nil {
		log.Fatalf("Failed to read signed JSON file: %v", err)
	}

	var signedUser SignedUser
	err = json.Unmarshal(signedData, &signedUser)
	if err != nil {
		log.Fatalf("Failed to unmarshal signed JSON data: %v", err)
	}

	// Load the public key
	publicKey, err := signing.LoadPublicKey("public_key.pem")
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	// Verify the signature
	userData, err := json.MarshalIndent(signedUser.User, "", INDENT)
	if err != nil {
		log.Fatalf("Failed to marshal user data: %v", err)
	}

	err = signing.VerifySignature(publicKey, userData, signedUser.Signature)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	fmt.Println("Signature verified successfully")
}
