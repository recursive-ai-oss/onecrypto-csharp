// Command godriver runs Go's crypto/x509 verification over every case of a cases.jsonl and prints `id<TAB>ACCEPT|REJECT<TAB>detail`.
// It uses only the standard library's documented API.
//
// Usage: godriver cases.jsonl > out.tsv
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

type testCase struct {
	ID        string   `json:"id"`
	Trusted   []string `json:"trusted"`
	Untrusted []string `json:"untrusted"`
	Leaf      string   `json:"leaf"`
	Time      *string  `json:"time"`
	Name      *string  `json:"name"`
	Profile   string   `json:"profile"`
	EKU       *string  `json:"eku"`
	MaxDepth  *int     `json:"maxDepth"`
}

func parse(pems []string) []*x509.Certificate {
	var out []*x509.Certificate
	for _, p := range pems {
		for {
			var b *pem.Block
			b, rest := pem.Decode([]byte(p))
			if b == nil {
				break
			}
			p = string(rest)
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				out = append(out, c)
			}
		}
	}
	return out
}

func verdict(c testCase) (bool, string) {
	leaves := parse([]string{c.Leaf})
	if len(leaves) != 1 {
		return false, "leaf not parsed"
	}
	roots := x509.NewCertPool()
	for _, r := range parse(c.Trusted) {
		roots.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, i := range parse(c.Untrusted) {
		inter.AddCert(i)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: time.Now()}
	if c.Time != nil {
		t, err := time.Parse(time.RFC3339Nano, *c.Time)
		if err != nil {
			return false, "bad time"
		}
		opts.CurrentTime = t
	}
	if c.EKU != nil {
		switch *c.EKU {
		case "serverAuth":
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "clientAuth":
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	} else {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if _, err := leaves[0].Verify(opts); err != nil {
		return false, err.Error()
	}
	if c.Name != nil {
		if err := leaves[0].VerifyHostname(*c.Name); err != nil {
			return false, err.Error()
		}
	}
	return true, ""
}

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		var c testCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			continue
		}
		ok, why := verdict(c)
		v := "REJECT"
		if ok {
			v = "ACCEPT"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.ID, v, strings.ReplaceAll(why, "\t", " "))
	}
}
