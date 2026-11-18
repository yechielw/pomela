package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func totp(seed string, now time.Time) (string, error) {
	digits, period := 6, 30
	var algorithm func() hash.Hash = sha1.New
	if strings.HasPrefix(seed, "otpauth://") {
		u, err := url.Parse(seed)
		if err != nil || u.Host != "totp" {
			return "", errors.New("invalid TOTP URI")
		}
		q := u.Query()
		seed = q.Get("secret")
		switch strings.ToUpper(q.Get("algorithm")) {
		case "", "SHA1":
		case "SHA256":
			algorithm = sha256.New
		case "SHA512":
			algorithm = sha512.New
		default:
			return "", errors.New("unsupported TOTP algorithm")
		}
		if s := q.Get("digits"); s != "" {
			digits, _ = strconv.Atoi(s)
		}
		if s := q.Get("period"); s != "" {
			period, _ = strconv.Atoi(s)
		}
	}
	if (digits != 6 && digits != 8) || period < 1 || period > 300 {
		return "", errors.New("invalid TOTP digits or period")
	}
	seed = strings.ToUpper(strings.TrimRight(strings.Join(strings.Fields(seed), ""), "="))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	if err != nil || len(key) < 10 {
		return "", errors.New("invalid TOTP seed (expected Base32 or otpauth URI)")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/int64(period)))
	mac := hmac.New(algorithm, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", digits, code%modulus), nil
}
