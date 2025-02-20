package main

import (
	"github.com/spf13/pflag"
)

var (
	flags *Flags
)

type Flags struct {
	InterfaceName string
	LogLevel      string
	IPRangesFile  string
	Port          string
	BindAddress   string
	SkipDNS       bool
}

func ParseFlags() *Flags {
	flags := &Flags{}

	pflag.StringVarP(&flags.InterfaceName, "interface", "i", "eth0", "Interface name to attach")
	pflag.StringVarP(&flags.LogLevel, "log-level", "l", "error", "Log level")
	pflag.StringVarP(&flags.IPRangesFile, "ip-ranges-filename", "f", "", "IP Ranges filename")
	pflag.StringVarP(&flags.BindAddress, "bind-address", "b", "", "Bind address")
	pflag.StringVarP(&flags.Port, "port", "p", "2112", "Port to listen to")
	pflag.BoolVarP(&flags.SkipDNS, "skip-dns", "n", false, "Skip reverse DNS lookups")

	pflag.Parse()

	return flags
}
