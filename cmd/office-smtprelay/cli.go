package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kgooris/office-smtprelay/internal/config"
	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/store"
)

// The CLI is a headless way to manage clients and the Microsoft connection.
// The web UI offers the same functions.

func openStoreFromEnv() (*store.Store, error) {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	return openStore(cfg)
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func runClient(args []string) error {
	if len(args) == 0 {
		return errors.New("client: missing subcommand (add, list, delete, enable, disable, passwd, setip)")
	}
	sub, args := args[0], args[1:]
	st, err := openStoreFromEnv()
	if err != nil {
		return err
	}
	defer st.Close()

	switch sub {
	case "add":
		fs := newFlags("client add")
		name := fs.String("name", "", "display name of the device")
		ip := fs.String("ip", "", "fixed IP address or network (CIDR) of the device")
		user := fs.String("user", "", "SMTP username (default: name in lower case)")
		pass := fs.String("password", "", "password (default: generated; avoid typing it on the command line)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *user == "" {
			*user = strings.ToLower(strings.ReplaceAll(*name, " ", "-"))
		}
		generated := false
		if *pass == "" {
			if *pass, err = store.GeneratePassword(20); err != nil {
				return err
			}
			generated = true
		}
		c, err := st.AddClient(*name, *ip, *user, *pass)
		if err != nil {
			return err
		}
		fmt.Printf("Client %q added.\n  Allowed from : %s\n  Username     : %s\n", c.Name, c.AddrString(), c.Username)
		if generated {
			fmt.Printf("  Password     : %s\n\nThis password is shown only once.\n", *pass)
		}
		return nil

	case "list":
		list, err := st.ListClients()
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Println("No clients registered.")
			return nil
		}
		fmt.Printf("%-24s %-20s %-20s %-8s %s\n", "NAME", "ALLOWED FROM", "USERNAME", "ENABLED", "LAST SEEN")
		for _, c := range list {
			seen := "never"
			if !c.LastSeen.IsZero() {
				seen = c.LastSeen.Local().Format("2006-01-02 15:04")
			}
			fmt.Printf("%-24s %-20s %-20s %-8v %s\n", c.Name, c.AddrString(), c.Username, c.Enabled, seen)
		}
		return nil

	case "delete", "enable", "disable":
		if len(args) != 1 {
			return fmt.Errorf("client %s: expected exactly one NAME", sub)
		}
		switch sub {
		case "delete":
			err = st.DeleteClient(args[0])
		case "enable":
			err = st.SetClientEnabled(args[0], true)
		default:
			err = st.SetClientEnabled(args[0], false)
		}
		if err == nil {
			fmt.Printf("Client %q: %s done.\n", args[0], sub)
		}
		return err

	case "setip":
		if len(args) != 2 {
			return errors.New("client setip: expected NAME and IP[/PREFIX]")
		}
		if err := st.SetClientAddr(args[0], args[1]); err != nil {
			return err
		}
		fmt.Printf("Client %q now allowed from %s.\n", args[0], args[1])
		return nil

	case "passwd":
		if len(args) < 1 {
			return errors.New("client passwd: expected NAME")
		}
		name := args[0]
		fs := newFlags("client passwd")
		pass := fs.String("password", "", "new password (default: generated)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		generated := false
		if *pass == "" {
			if *pass, err = store.GeneratePassword(20); err != nil {
				return err
			}
			generated = true
		}
		if err := st.SetClientPassword(name, *pass); err != nil {
			return err
		}
		fmt.Printf("Password of %q changed.\n", name)
		if generated {
			fmt.Printf("  New password : %s\n\nThis password is shown only once.\n", *pass)
		}
		return nil
	}
	return fmt.Errorf("client: unknown subcommand %q", sub)
}

func runGraph(args []string) error {
	if len(args) == 0 {
		return errors.New("graph: missing subcommand (set, show, check)")
	}
	sub, args := args[0], args[1:]
	st, err := openStoreFromEnv()
	if err != nil {
		return err
	}
	defer st.Close()

	switch sub {
	case "set":
		fs := newFlags("graph set")
		tenant := fs.String("tenant", "", "Directory (tenant) ID")
		client := fs.String("client", "", "Application (client) ID")
		expires := fs.String("expires", "", "expiry date of the client secret, YYYY-MM-DD (enables the expiry warning)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		secret := strings.TrimSpace(os.Getenv("SMTPRELAY_CLIENT_SECRET"))
		if secret == "" {
			fmt.Fprintln(os.Stderr, "Paste the client secret value and press Enter (input is not stored in shell history):")
			secret = readLine(os.Stdin)
		}
		var exp time.Time
		if *expires != "" {
			if exp, err = time.Parse("2006-01-02", *expires); err != nil {
				return fmt.Errorf("--expires: %w", err)
			}
		}
		if err := st.SetGraphCredentials(graph.Credentials{TenantID: strings.TrimSpace(*tenant), ClientID: strings.TrimSpace(*client), ClientSecret: secret}, exp); err != nil {
			return err
		}
		fmt.Println("Microsoft connection saved (secret stored encrypted). Run 'graph check' to validate it.")
		return nil

	case "show":
		creds, ok, err := st.GraphCredentials()
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Microsoft connection: not configured")
			return nil
		}
		fmt.Printf("Tenant ID     : %s\nClient ID     : %s\nClient secret : set\n", creds.TenantID, creds.ClientID)
		if exp, ok := st.SecretExpires(); ok {
			fmt.Printf("Secret expires: %s (%d days)\n", exp.Format("2006-01-02"), int(time.Until(exp).Hours()/24))
		}
		return nil

	case "check":
		creds, ok, err := st.GraphCredentials()
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("the Microsoft connection is not configured (use 'graph set')")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := graph.New(creds).CheckCredentials(ctx); err != nil {
			return err
		}
		fmt.Println("OK: Microsoft accepted the tenant ID, client ID and client secret.")
		return nil
	}
	return fmt.Errorf("graph: unknown subcommand %q", sub)
}

func readLine(r io.Reader) string {
	s, _ := bufio.NewReader(r).ReadString('\n')
	return strings.TrimSpace(s)
}
