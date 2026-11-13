package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kgooris/office-smtprelay/internal/config"
	"github.com/kgooris/office-smtprelay/internal/store"
)

// runBackup implements "backup export [FILE]" and "backup import FILE".
func runBackup(args []string) error {
	if len(args) == 0 || (args[0] != "export" && args[0] != "import") {
		return fmt.Errorf("usage: backup export [FILE] | backup import FILE")
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

	if args[0] == "export" {
		b, err := st.ExportBackup()
		if err != nil {
			return err
		}
		out := io.Writer(os.Stdout)
		if len(args) > 1 {
			f, err := os.OpenFile(args[1], os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			out = f
			fmt.Fprintf(os.Stderr, "Backup written to %s. It contains password hashes: keep it private.\n", args[1])
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(b)
	}

	if len(args) != 2 {
		return fmt.Errorf("usage: backup import FILE")
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	var b store.Backup
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("not a backup file: %w", err)
	}
	res, err := st.ImportBackup(b)
	if err != nil {
		return err
	}
	fmt.Printf("Imported: %d device(s) added, %d updated. The Microsoft connection and the admin password are not part of a backup.\n", res.Added, res.Updated)
	return nil
}
