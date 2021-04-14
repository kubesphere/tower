package main

import (
	"log"

	"kubesphere.io/tower/cmd/agent/app"
)

func main() {
	cmd := app.NewAgentCommand()

	if err := cmd.Execute(); err != nil {
		log.Fatalln(err)
	}
}
