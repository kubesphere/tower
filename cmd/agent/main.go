package main

import (
	"github.com/zryfish/tower/cmd/agent/app"
	"log"
)

func main() {
	cmd := app.NewAgentCommand()

	if err := cmd.Execute(); err != nil {
		log.Fatalln(err)
	}
}
