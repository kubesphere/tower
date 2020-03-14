package main

import (
	"kubesphere.io/tower/cmd/proxy/app"
	"log"
)

func main() {
	command := app.NewProxyCommand()

	if err := command.Execute(); err != nil {
		log.Fatalln(err)
	}
}
