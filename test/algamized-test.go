package main

// #include "../dist/portable8439.h"
// #include "../dist/portable8439.c"
import "C"

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

func bytePointer(ar []byte) *C.uint8_t {
	return (*C.uint8_t)(&ar[0])
}

func poly1305chacha20Interop() {
	fmt.Println("Encrypting plaintext using C")
	var key [C.RFC_8439_KEY_SIZE]byte
	var nonce [C.RFC_8439_NONCE_SIZE]byte
	rand.Read(key[:])
	rand.Read(nonce[:])

	var plain [8000]byte
	var ad [500]byte

	rand.Read(plain[:])
	rand.Read(ad[:])

	var cipher [len(plain) + C.RFC_8439_TAG_SIZE]byte

	C.portable_chacha20_poly1305_encrypt(bytePointer(cipher[:]),
		bytePointer(key[:]), bytePointer(nonce[:]),
		bytePointer(ad[:]), C.size_t(len(ad)),
		bytePointer(plain[:]), C.size_t(len(plain)))

	fmt.Println("Decrypting cyphertext using go")
	aead, _ := chacha20poly1305.New(key[:])
	decrypted, err := aead.Open(nil, nonce[:], cipher[:], ad[:])
	if err != nil {
		log.Fatalf("Failure to decrypt: %v", err)
	}

	if bytes.Equal(plain[:], decrypted[:]) {
		fmt.Println("Success")
	} else {
		log.Fatal("Failure to decrypt")
	}
}

func main() {
	poly1305chacha20Interop()
}
