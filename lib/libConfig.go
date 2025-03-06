package lib

import (
	"errors"
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

var Config *viper.Viper

func LoadConfig() error {
	Config = viper.New()
	Config.SetConfigName("jwtplus")
	Config.SetConfigType("yaml")
	Config.AddConfigPath(".")
	Config.AddConfigPath("/etc/jwtplus/")
	Config.AddConfigPath("/opt/jwtplus/")

	//Set Defaults
	Config.SetDefault("debug", false)
	err := Config.ReadInConfig()
	if err != nil {
		return err
	}
	return nil
}

func VerifyConfig() error {
	type Domain struct {
		FQDN string `validate:"fqdn"`
	}

	type IpAdd struct {
		IP string `validate:"ip"`
	}

	type Origin struct {
		URL string `validate:"http_url"`
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	if !Config.IsSet("server.ip") && !Config.IsSet("server.domain") {
		return errors.New("missing config for ip/domain, either set ip address or domain in the config file")
	}

	if Config.IsSet("server.ip") && Config.IsSet("server.domain") {
		return errors.New("can't start service. ip address & domain both are set in config. choose either ip address or domain")
	}

	if Config.IsSet("server.ip") {
		validateIP := &IpAdd{
			IP: Config.GetString("server.ip"),
		}

		if err := validate.Struct(validateIP); err != nil {
			return fmt.Errorf("%s is not a valid ip address. please set the valid ip address", validateIP.IP)
		}
	}

	if Config.IsSet("server.domain") {
		validateFQDN := &Domain{
			FQDN: Config.GetString("server.domain"),
		}

		if err := validate.Struct(validateFQDN); err != nil {
			return fmt.Errorf("%s is not a valid domain name. please set the valid domain.", validateFQDN.FQDN)
		}
	}

	if Config.IsSet("origins") {
		for _, o := range Config.GetStringSlice("origins") {
			validateOrigins := Origin{
				URL: o,
			}

			if err := validate.Struct(validateOrigins); err != nil {
				return fmt.Errorf("%s is not a valid origin in config, origin must start either with http or https", o)
			}
		}
	}

	if !Config.IsSet("db.location") ||
		!Config.IsSet("db.username") ||
		!Config.IsSet("db.password") ||
		!Config.IsSet("db.port") ||
		!Config.IsSet("db.dbname") {
		return errors.New("missing config for database")
	}

	return nil
}
