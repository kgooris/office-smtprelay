package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kgooris/office-smtprelay/internal/config"
	"github.com/kgooris/office-smtprelay/internal/store"
)

// runUser implements the commands that get you back into the web UI when you
// are locked out (lost password, lost phone, wrong network restriction):
//
//	user list
//	user add NAME [--role admin|readonly] [--password P]
//	user passwd NAME [--password P]
//	user reset-2fa NAME
//	user delete NAME
//	user reset-access        (removes the network restriction of the web UI)
func runUser(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: user list|add|passwd|reset-2fa|delete|reset-access")
	}
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	role := fs.String("role", store.RoleAdmin, "admin or readonly")
	pass := fs.String("password", "", "password (generated when empty)")
	// flags may come after the name
	var names []string
	for len(rest) > 0 {
		if strings.HasPrefix(rest[0], "-") {
			if err := fs.Parse(rest); err != nil {
				return err
			}
			rest = fs.Args()
			continue
		}
		names = append(names, rest[0])
		rest = rest[1:]
	}
	needName := func() (store.User, error) {
		if len(names) != 1 {
			return store.User{}, fmt.Errorf("user %s: expected exactly one NAME", sub)
		}
		return st.UserByName(names[0])
	}
	password := func() (string, bool, error) {
		if *pass != "" {
			return *pass, false, nil
		}
		p, err := store.GeneratePassword(20)
		return p, true, err
	}

	switch sub {
	case "list":
		users, err := st.Users()
		if err != nil {
			return err
		}
		fmt.Printf("%-24s %-10s %-6s %s\n", "NAME", "ROLE", "2FA", "LAST SIGN-IN")
		for _, u := range users {
			last := "never"
			if !u.LastLogin.IsZero() {
				last = u.LastLogin.Local().Format("2006-01-02 15:04")
			}
			fmt.Printf("%-24s %-10s %-6v %s\n", u.Username, u.Role, u.TOTPEnabled, last)
		}
		return nil
	case "add":
		if len(names) != 1 {
			return fmt.Errorf("user add: expected exactly one NAME")
		}
		p, generated, err := password()
		if err != nil {
			return err
		}
		if _, err := st.AddUser(names[0], p, *role); err != nil {
			return err
		}
		fmt.Printf("User %q added as %s.\n", names[0], *role)
		if generated {
			fmt.Printf("  Password: %s\n\nThis password is shown only once.\n", p)
		}
		return nil
	case "passwd":
		u, err := needName()
		if err != nil {
			return err
		}
		p, generated, err := password()
		if err != nil {
			return err
		}
		if err := st.SetUserPassword(u.ID, p); err != nil {
			return err
		}
		fmt.Printf("Password of %q changed.\n", u.Username)
		if generated {
			fmt.Printf("  Password: %s\n\nThis password is shown only once.\n", p)
		}
		return nil
	case "reset-2fa":
		u, err := needName()
		if err != nil {
			return err
		}
		if err := st.DisableTOTP(u.ID); err != nil {
			return err
		}
		fmt.Printf("Two-step verification of %q switched off.\n", u.Username)
		return nil
	case "delete":
		u, err := needName()
		if err != nil {
			return err
		}
		if err := st.DeleteUser(u.ID); err != nil {
			return err
		}
		fmt.Printf("User %q deleted.\n", u.Username)
		return nil
	case "reset-access":
		if _, err := st.SetUIAllow(""); err != nil {
			return err
		}
		fmt.Println("The network restriction of the web interface was removed.")
		return nil
	}
	return fmt.Errorf("unknown command %q", "user "+sub)
}
