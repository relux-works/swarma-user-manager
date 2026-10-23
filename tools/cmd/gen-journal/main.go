package main

import (
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"os"
)

func main() { os.Exit(genjournal.Run(os.Args[1:], os.Stdout, os.Stderr)) }
