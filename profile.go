package main

import (
	"fmt"
	"strings"
)

type profile struct {
	email string
	uid   int
	role  string
}

func (p profile) toCookie() string {
	return fmt.Sprintf("email=%s&uid=%d&role=%s", p.email, p.uid, p.role)
}

func newProfile(email string, uid int, role string) profile {
	return profile{
		email,
		uid,
		role,
	}
}

func profileFor(email string) profile {
	email = strings.ReplaceAll(email, "&", "")
	email = strings.ReplaceAll(email, "=", "")

	return newProfile(email, 10, "user")
}
