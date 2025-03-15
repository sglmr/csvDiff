package main

import (
	"fmt"
	"log"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	// Try to read password securely first (won't echo characters)
	fmt.Print("   Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalln("could not get password: %w", err)
	}

	// Ask to re-enter password to confirm
	fmt.Print("\nRe-Enter password: ")
	passwordCheck, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalln("could not get re-entered password: %w", err)
	}

	// Exit if the passwords don't match
	if string(password) != string(passwordCheck) {
		log.Fatalln("passwords don't match")
	}

	// Generate the bcrypt hash
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		log.Fatalln("Error generating hash:", err)
	}

	// Print the resulting hash
	fmt.Println("\n\tPassword hash:", string(hash))
}
