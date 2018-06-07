// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/fernet/fernet-go"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair"
	"github.com/coreos/clair/api"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/notification"
	"github.com/spf13/viper"
)

// ErrDatasourceNotLoaded is returned when the datasource variable in the
// configuration file is not loaded properly
var ErrDatasourceNotLoaded = errors.New("could not load configuration: no database source specified")

// File represents a YAML configuration file that namespaces all Clair
// configuration under the top-level "clair" key.
type File struct {
	Clair Config `yaml:"clair"`
}

// Config is the global configuration for an instance of Clair.
type Config struct {
	Database database.RegistrableComponentConfig
	Updater  *clair.UpdaterConfig
	Notifier *notification.Config
	API      *api.Config
}

// clairConfig holds the Viper configuration for Clair
var clairConfig *viper.Viper

// DefaultConfig is a configuration that can be used as a fallback value.
func DefaultConfig() Config {
	return Config{
		Database: database.RegistrableComponentConfig{
			Type: "pgsql",
		},
		Updater: &clair.UpdaterConfig{
			Interval: 1 * time.Hour,
		},
		API: &api.Config{
			Port:       6060,
			HealthPort: 6061,
			Timeout:    900 * time.Second,
		},
		Notifier: &notification.Config{
			Attempts:         5,
			RenotifyInterval: 2 * time.Hour,
		},
	}
}

// LoadConfig is a shortcut to open a file, read it, and generate a Config.
//
// It supports relative and absolute paths. Given "", it returns DefaultConfig.
func LoadConfig(path string) (config *Config, err error) {

	if clairConfig == nil {
		clairConfig = viper.New()
		clairConfig.SetConfigName("clair")
		clairConfig.SetConfigFile(path)

		err = clairConfig.ReadInConfig()
	}
	// Any config variable can be read from environment variables prefixed with "CLAIR_"
	clairConfig.SetEnvPrefix("clair")
	clairConfig.AutomaticEnv()

	// Set values as loaded by Viper. I think this is short term fix - probably better to use the viper code in the rest of Clair...
	var cfgFile File
	cfgFile.Clair = DefaultConfig()
	cfgFile.Clair.Database.Options = map[string]interface{}{}

	if clairConfig.IsSet("clair.database.type") {
		cfgFile.Clair.Database.Type = clairConfig.GetString("clair.database.type")
	}
	if clairConfig.IsSet("clair.database.options.source") {
		cfgFile.Clair.Database.Options["source"] = clairConfig.GetString("clair.database.options.source")
	}
	if clairConfig.IsSet("clair.database.options.cachesize") {
		cfgFile.Clair.Database.Options["cachesize"] = clairConfig.GetString("clair.database.options.cachesize")
	}
	if clairConfig.IsSet("clair.database.options.paginationkey") {
		cfgFile.Clair.Database.Options["paginationkey"] = clairConfig.GetString("clair.database.options.paginationkey")
	}
	// if clairConfig.IsSet("clair.database.api.addr") {
	// 	cfgFile.Clair.API.Addr = clairConfig.GetString("clair.database.api.addr")
	// }
	if clairConfig.IsSet("clair.database.api.healthaddr") {
		cfgFile.Clair.API.HealthPort = clairConfig.GetInt("clair.database.api.healthport")
	}
	if clairConfig.IsSet("clair.database.api.timeout") {
		cfgFile.Clair.API.Timeout, err = time.ParseDuration(clairConfig.GetString("clair.database.api.timeout"))
		if err != nil {
			return
		}
	}
	// database.api.servername is in sample config, but looks like not referenced in code?
	if clairConfig.IsSet("clair.database.api.cafile") {
		cfgFile.Clair.API.CAFile = clairConfig.GetString("clair.database.api.cafile")
	}
	if clairConfig.IsSet("clair.database.api.keyfile") {
		cfgFile.Clair.API.KeyFile = clairConfig.GetString("clair.database.api.keyfile")
	}
	if clairConfig.IsSet("clair.database.api.certfile") {
		cfgFile.Clair.API.CertFile = clairConfig.GetString("clair.database.api.certfile")
	}
	// if clairConfig.IsSet("clair.database.worker.namespace_detectors") {
	// 	cfgFile.Clair.Worker.EnabledDetectors = clairConfig.GetStringSlice("clair.database.worker.namespace_detectors")
	// }
	// if clairConfig.IsSet("clair.database.worker.feature_listers") {
	// 	cfgFile.Clair.Worker.EnabledListers = clairConfig.GetStringSlice("clair.database.worker.feature_listers")
	// }
	if clairConfig.IsSet("clair.database.updater.interval") {
		cfgFile.Clair.Updater.Interval, err = time.ParseDuration(clairConfig.GetString("clair.database.updater.interval"))
		if err != nil {
			return
		}
	}
	// if clairConfig.IsSet("clair.database.updater.enabledupdaters") {
	// 	cfgFile.Clair.Updater.EnabledUpdaters = clairConfig.GetStringSlice("clair.database.updater.enabledupdaters")
	// }
	if clairConfig.IsSet("clair.database.notifier.attempts") {
		cfgFile.Clair.Notifier.Attempts = clairConfig.GetInt("clair.database.updater.attempts")
	}
	if clairConfig.IsSet("clair.database.notifier.renotifyinterval") {
		cfgFile.Clair.Notifier.RenotifyInterval, err = time.ParseDuration(clairConfig.GetString("clair.database.updater.renotifyinterval"))
		if err != nil {
			return
		}
	}
	if clairConfig.IsSet("clair.database.notifier.http") {
		config.Notifier.Params["http"] = clairConfig.GetString("clair.database.updater.http")
		// debug - just checking that this works...
		fmt.Printf("clair.database.notifier.http: %s", clairConfig.GetString("clair.database.updater.http"))
	}

	// Generate a pagination key if none is provided.
	if !clairConfig.IsSet("clair.database.options.paginationkey") {
		log.Warn("pagination key is empty, generating...")
		var key fernet.Key
		if err = key.Generate(); err != nil {
			return
		}
		cfgFile.Clair.Database.Options["paginationkey"] = key.Encode()
	} else {
		config.Database.Options["paginationkey"] = clairConfig.GetString("paginationkey")
		_, err = fernet.DecodeKey(clairConfig.GetString("paginationkey"))
		if err != nil {
			err = errors.New("Invalid Pagination key; must be 32-bit URL-safe base64")
			return
		}
	}
	config = &cfgFile.Clair
	return
}
