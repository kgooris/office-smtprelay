// Command office-smtprelay is a local SMTP relay that forwards mail to
// Microsoft 365 through the Graph API.
package main

import (
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usageText = `office-smtprelay ` + "%s" + `

Usage:
  office-smtprelay [serve]                      run the relay (default)
  office-smtprelay healthcheck                  exit 0 if the running relay is healthy
  office-smtprelay client add --name N --ip IP[/PREFIX] --user U [--password P]
  office-smtprelay client list
  office-smtprelay client delete|enable|disable NAME
  office-smtprelay client passwd NAME [--password P]
  office-smtprelay client setip NAME IP[/PREFIX]
  office-smtprelay graph set --tenant ID --client ID [--expires YYYY-MM-DD]
                                                (secret from $SMTPRELAY_CLIENT_SECRET or stdin)
  office-smtprelay graph show
  office-smtprelay graph check                  request a token to validate the Microsoft connection
  office-smtprelay user list|add|passwd|reset-2fa|delete|reset-access   web UI users; recovery when locked out
  office-smtprelay backup export [FILE]         write the devices, rules and settings as JSON (no secrets)
  office-smtprelay backup import FILE           restore from such a file (merges by device name)
  office-smtprelay pause|resume                 emergency stop: pause or resume all sending
  office-smtprelay version

Configuration is read from SMTPRELAY_* environment variables (see README).
`

func usage() { fmt.Fprintf(os.Stderr, usageText, version) }

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = runServe()
	case "healthcheck":
		err = runHealthcheck()
	case "client":
		err = runClient(args)
	case "graph":
		err = runGraph(args)
	case "backup":
		err = runBackup(args)
	case "user":
		err = runUser(args)
	case "pause", "resume":
		err = runPause(cmd == "pause")
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
