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
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"

	"github.com/cilium/cilium/pkg/types"
	"github.com/sirupsen/logrus"
)

var IpRanges IPRanges

// SVC holds lists of CIDR blocks for IPv4 and IPv6.
type SVC struct {
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
	Name string   `json:"name"`
}

// Data represents the entire JSON structure with dynamic keys.
type IPRanges []SVC

type IP4Key struct {
	PrefixLen uint32
	IP        types.IPv4
}

type IP6Key struct {
	PrefixLen uint32
	IP        types.IPv6
}

func newIP4Key(IP net.IP, sourceMask net.IPMask) IP4Key {
	key := IP4Key{}

	ones, _ := sourceMask.Size()
	copy(key.IP[:], IP.To4())
	key.PrefixLen = uint32(ones)

	return key
}

func newIP6Key(IP net.IP, sourceMask net.IPMask) IP6Key {
	key := IP6Key{}

	ones, _ := sourceMask.Size()
	copy(key.IP[:], IP.To16())
	key.PrefixLen = uint32(ones)

	return key
}

func setupIPRanges(fname string) {
	if fname != "" {
		logrus.Infof("Loading IP ranges from %s", fname)
	} else {
		logrus.Info("No IP ranges file specified")
		return
	}

	irf, err := os.Open(fname)
	if err != nil {
		logrus.Fatalf("Failed to open IP ranges file: %s", err)
		return
	}
	defer irf.Close()

	bs, err := io.ReadAll(irf)

	if err != nil {
		logrus.Fatalf("Failed to read IP ranges file: %s", err)
		return
	}

	err = json.Unmarshal(bs, &IpRanges)
	if err != nil {
		logrus.Fatalf("Failed to parse IP ranges file: %s", err)
		return
	}

	for idx, svc := range IpRanges {

		var keySlice []IP4Key
		var valueSlice []uint32

		var keySlice6 []IP6Key
		var valueSlice6 []uint32

		for _, ip := range svc.IPv4 {
			if !strings.Contains(ip, "/") {

				ip += "/32"

			}

			IP, IPNet, err := net.ParseCIDR(ip)

			if err != nil {
				logrus.Warnf("Malformed ip %v \n", err)
				continue
			}

			key := newIP4Key(IP, IPNet.Mask)
			keySlice = append(keySlice, key)
			valueSlice = append(valueSlice, uint32(idx))
		}

		count, err := objs.cntMaps.Ip4LpmTrie.BatchUpdate(keySlice, valueSlice, nil)
		if err != nil {
			logrus.Fatalf("BatchUpdate: %v", err)
		}
		if count != len(keySlice) {
			logrus.Fatalf("BatchUpdate: expected count, %d, to be %d", count, len(keySlice))
		}

		for _, ip := range svc.IPv6 {
			if !strings.Contains(ip, "/") {

				ip += "/128"

			}

			IP, IPNet, err := net.ParseCIDR(ip)

			if err != nil {
				logrus.Warnf("malformed ip %v \n", err)
				continue
			}

			key := newIP6Key(IP, IPNet.Mask)
			keySlice6 = append(keySlice6, key)
			valueSlice6 = append(valueSlice6, uint32(idx))
		}

		count6, err := objs.cntMaps.Ip6LpmTrie.BatchUpdate(keySlice6, valueSlice6, nil)
		if err != nil {
			logrus.Fatalf("BatchUpdate: %v", err)
		}
		if count6 != len(keySlice6) {
			logrus.Fatalf("BatchUpdate: expected count, %d, to be %d", count6, len(keySlice6))
		}
	}
}
