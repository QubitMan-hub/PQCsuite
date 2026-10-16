package main

import "flag"

var useECDSA = flag.Bool("ecdsa", false, "generate an ECDSA key instead of RSA")

func main() {
	flag.Parse()
}
