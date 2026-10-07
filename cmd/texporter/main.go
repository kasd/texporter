// Copyright 2024 Anton Kulpinov

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/dnscache"
	"github.com/sirupsen/logrus"
)

var (
	resolver *dnscache.Resolver
)

func init() {
	flags = ParseFlags()
}

func main() {

	lvl, err := logrus.ParseLevel(flags.LogLevel)
	if err == nil {
		logrus.SetLevel(logrus.Level(lvl))
	}

	ifn := flags.InterfaceName

	// Start HTTP server for Prometheus metrics
	go func() {
		http.Handle("/metrics", promhttp.Handler())

		bindAddress := flags.BindAddress

		if bindAddress == "" {
			bindAddress = fmt.Sprintf(":%s", flags.Port)
		}

		logrus.Fatal(http.ListenAndServe(bindAddress, nil))
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Fatal("Removing memlock:", err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := loadCntObjects(&objs, nil); err != nil {
		logrus.Fatal("Loading eBPF objects:", err)
		os.Exit(-1)
	}
	defer objs.Close()

	setupIPRanges(flags.IPRangesFile)

	iface, err := net.InterfaceByName(ifn)
	if err != nil {
		logrus.Fatalf("Getting interface %s: %s", ifn, err)
		os.Exit(-1)
	}

	// Attach xdp to the network interface. Native/driver mode (the default) is fastest, but is
	// unavailable on some interfaces (e.g. veth in nested containers / Kubernetes pods), where the
	// kernel returns ERANGE. In that case fall back to generic/SKB mode, which works on any netdev.
	var xdpFlags link.XDPAttachFlags
	if flags.XDPMode == "generic" {
		xdpFlags = link.XDPGenericMode
	}
	iLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CntXdpProgFunc,
		Interface: iface.Index,
		Flags:     xdpFlags,
	})
	if err != nil && xdpFlags == 0 {
		logrus.Warnf("Native XDP attach failed (%s); retrying in generic/SKB mode", err)
		iLink, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.CntXdpProgFunc,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
	}
	if err != nil {
		logrus.Fatalf("Attaching XDP: %s", err)
		os.Exit(-1)
	}
	defer iLink.Close()

	// Attach tc to the network interface.
	eLink, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.CntTcProgFunc,
		Attach:    ebpf.AttachTCXEgress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attaching TCX egress: %s", err)
	}
	defer eLink.Close()

	if !flags.SkipDNS {
		resolver = &dnscache.Resolver{}

		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for range t.C {
				resolver.Refresh(false)
			}
		}()
	}

	logrus.Info("Start counting packets..")

	// Clean up stale metrics every 5 minutes
	go func() {
		for range time.Tick(5 * time.Minute) {
			cleanUpStaleMetrics()
		}
	}()

	// Create a new prometheus collector
	collector := newTrafficmonCollector()
	prometheus.MustRegister(collector)

	<-stopper

	os.Exit(0)
}
