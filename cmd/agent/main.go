package main

import (
	"kubesphere.io/tower/cmd/agent/app"
	"log"
)

func main() {
	cmd := app.NewAgentCommand()

	if err := cmd.Execute(); err != nil {
		log.Fatalln(err)
	}
}
