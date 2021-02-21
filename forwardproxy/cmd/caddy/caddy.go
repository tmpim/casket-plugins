package main

import (
	_ "github.com/tmpim/casket-plugins/forwardproxy"
	"github.com/tmpim/casket/casket/casketmain"
)

func main() {
	casketmain.EnableTelemetry = false
	casketmain.Run()
}
