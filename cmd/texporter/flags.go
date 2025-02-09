package main

import "github.com/spf13/pflag"

type Flags struct {
	InterfaceName string
	LogLevel      string
	IPRangesFile  string
	Port          string
}

func ParseFlags() *Flags {
	flags := &Flags{}

	pflag.StringVarP(&flags.InterfaceName, "interface", "i", "eth0", "Interface name to attach")
	pflag.StringVarP(&flags.LogLevel, "log-level", "l", "info", "Log level")
	pflag.StringVarP(&flags.IPRangesFile, "ip-ranges-filename", "f", "", "IP Ranges filename")
	pflag.StringVarP(&flags.Port, "port", "p", "2112", "Port to listen to")

	pflag.Parse()

	return flags
}
