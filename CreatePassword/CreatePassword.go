package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"log"
	rand2 "math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	var err error
	var password string
	var salt []byte
	var iterations int
	if len(os.Args) > 1 {
		password = os.Args[1]
	}
	if len(os.Args) > 2 {
		salt, err = base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			log.Fatal("invalid salt: " + err.Error())
		}
	}
	if len(os.Args) > 3 {
		iterations, err = strconv.Atoi(os.Args[3])
		if err != nil {
			log.Fatalln("invalid number of iterations")
		}
	}

	var random = rand2.New(rand2.NewSource(time.Now().UnixNano()))
	if password == "" {
		var builder = strings.Builder{}
		for i := 0; i < 20; i++ {
			builder.WriteByte(byte(random.Intn(94) + 33))
		}
		password = builder.String()
	}
	if len(salt) == 0 {
		salt = make([]byte, 64)
		_, _ = rand.Read(salt)
	}
	if iterations == 0 {
		//just following OWASP https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html at the time of writing
		iterations = 600000 + rand2.Intn(100000)
	}

	var saltedPassword = make([]byte, sha256.Size)
	var intermediate = binary.BigEndian.AppendUint32(salt, 1)
	var hasher = hmac.New(sha256.New, []byte(password))
	for i := 0; i < iterations; i++ {
		hasher.Write(intermediate)
		intermediate = hasher.Sum(nil)
		hasher.Reset()
		for j, b := range intermediate {
			saltedPassword[j] = saltedPassword[j] ^ b
		}
	}
	var encoded = base64.StdEncoding.EncodeToString(saltedPassword)
	var buffer = make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	_, _ = base64.StdEncoding.Decode(buffer, []byte(encoded))
	hasher = hmac.New(sha256.New, buffer)
	hasher.Write([]byte("Client Key"))

	print("Password: ")
	println(password)
	print("Salt: ")
	println(base64.StdEncoding.EncodeToString(salt))
	print("Iterations: ")
	println(iterations)
	print("Hash: ")
	println(base64.StdEncoding.EncodeToString(buffer))
}
