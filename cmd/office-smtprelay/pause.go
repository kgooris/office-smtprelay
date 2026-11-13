package main

import (
	"fmt"
	"os"

	"github.com/kgooris/office-smtprelay/internal/config"
)

// runPause switches the emergency stop on or off. It works on the database, so
// it takes effect immediately in the running relay.
func runPause(pause bool) error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.SetPaused(pause); err != nil {
		return err
	}
	if pause {
		fmt.Println("Sending is paused. Devices are told to try again later. Run 'resume' to continue.")
	} else {
		fmt.Println("Sending resumed.")
	}
	return nil
}
