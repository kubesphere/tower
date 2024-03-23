// 
package main

import (
	"log"

	"kubesphere.io/tower/cmd/proxy/app"
)

func main() {
	cmd := app.NewProxyCommand()

	if err := cmd.Execute(); err != nil {
		log.Fatalln(err)
	}
}
