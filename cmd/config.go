package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func initConfig() {
	v := viper.New()

	if _, err := os.Stat(config); errors.Is(err, os.ErrNotExist) {
		if rootCmd.Flags().Lookup("config").Changed {
			log.Fatalf("config file %s does not exist", config)
		} else {
			log.Printf("%s does not exist, using command line arguments", config)
			return
		}
	}

	v.SetConfigFile(config)

	if v.ConfigFileUsed() != "" {
		log.Println("Using config file:", v.ConfigFileUsed())
	}

	if err := v.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	//Currently we do not accept configuration for root commands
	commands := rootCmd.Commands()

	for _, cmd := range commands {
		flags := cmd.Flags()
		flags.VisitAll(func(f *pflag.Flag) {
			configKey := fmt.Sprintf("%s.%s", cmd.Name(), f.Name)
			configValue := v.GetString(configKey)
			if configValue != "" && !f.Changed {
				f.Value.Set(v.GetString(configKey))
			}
		})
	}
}
