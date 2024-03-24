package security

import "os"

var privateKey = ""

func GetPrivateKey() string {
	if privateKey != "" {
		return privateKey
	}
	return os.Getenv("pk")
}

func GetUser() string {
	return "hwj"
}

func GetPwd() string {
	return "Qq321654"
}
