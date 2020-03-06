package main

import (
	"github.com/zryfish/tower/cmd/proxy/app"
	"log"
)

func main() {
	command := app.NewProxyCommand()

	if err := command.Execute(); err != nil {
		log.Fatalln(err)
	}
}
