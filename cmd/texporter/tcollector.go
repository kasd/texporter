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
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const (
	// Flags for IP addresses
	FLAG_NONE  = 0x0
	FLAG_SRC_I = 0x1
	FLAG_DST_I = 0x2
)

var (
	mu   sync.Mutex
	objs cntObjects
)

type trafficmonCollector struct {
	trafficMonCapturedBytes  *prometheus.Desc
	trafficMon6CapturedBytes *prometheus.Desc
}

func newTrafficmonCollector() *trafficmonCollector {
	return &trafficmonCollector{
		trafficMonCapturedBytes: prometheus.NewDesc("trafficmon_captured_bytes",
			"The total number of bytes captured by trafficmon exporter",
			[]string{"src", "dst"}, nil,
		),
		trafficMon6CapturedBytes: prometheus.NewDesc("trafficmon6_captured_bytes",
			"The total number of bytes captured by trafficmon exporter IPv6",
			[]string{"src", "dst"}, nil,
		),
	}
}

func (collector *trafficmonCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.trafficMonCapturedBytes
}

// Collect implements required collect function for all promehteus collectors
func (collector *trafficmonCollector) Collect(ch chan<- prometheus.Metric) {
	logrus.Info("Collecting metrics..")

	// Process counters
	processCounters(collector, ch)
}

func handleIp4Pair(wg *sync.WaitGroup, c *trafficmonCollector, ch chan<- prometheus.Metric, key cntIp4PairAddrKey, val cntIp4PairValue) {
	var (
		src [4]byte
		dst [4]byte
	)

	defer wg.Done()

	binary.LittleEndian.PutUint32(src[:], key.Src)
	binary.LittleEndian.PutUint32(dst[:], key.Dst)

	ipSrc := netip.AddrFrom4(src).String()
	ipDst := netip.AddrFrom4(dst).String()

	ch <- prometheus.MustNewConstMetric(c.trafficMonCapturedBytes, prometheus.CounterValue, float64(val.Bytes), ipSrc, ipDst)
}

func hadnleIP4PairAgg(wg *sync.WaitGroup, c *trafficmonCollector, ch chan<- prometheus.Metric, key cntIp4PairAddrValue, val cntIp4PairValue) {
	var (
		src   [4]byte
		dst   [4]byte
		ipSrc string
		ipDst string
	)

	defer wg.Done()

	if key.Flags&FLAG_SRC_I == FLAG_SRC_I {
		ipSrc = IpRanges[key.Addrs.Src].Name
	} else {
		binary.LittleEndian.PutUint32(src[:], key.Addrs.Src)
		ipSrc = netip.AddrFrom4(src).String()
	}

	if key.Flags&FLAG_DST_I == FLAG_DST_I {
		ipDst = IpRanges[key.Addrs.Dst].Name
	} else {
		binary.LittleEndian.PutUint32(dst[:], key.Addrs.Dst)
		ipDst = netip.AddrFrom4(dst).String()

	}

	ch <- prometheus.MustNewConstMetric(c.trafficMonCapturedBytes, prometheus.CounterValue, float64(val.Bytes), ipSrc, ipDst)
}

func handleIp6Pair(wg *sync.WaitGroup, c *trafficmonCollector, ch chan<- prometheus.Metric, key cntIp6PairAddrKey, val cntIp6PairValue) {
	var (
		src [16]byte
		dst [16]byte
	)

	defer wg.Done()

	copy(src[:], key.Src.In6U.U6Addr8[:])
	copy(dst[:], key.Dst.In6U.U6Addr8[:])

	ipSrc := netip.AddrFrom16(src).String()
	ipDst := netip.AddrFrom16(dst).String()

	ch <- prometheus.MustNewConstMetric(c.trafficMon6CapturedBytes, prometheus.CounterValue, float64(val.Bytes), ipSrc, ipDst)
}

func hadnleIP6PairAgg(wg *sync.WaitGroup, c *trafficmonCollector, ch chan<- prometheus.Metric, key cntIp6PairAddrValue, val cntIp6PairValue) {
	var (
		src   [16]byte
		dst   [16]byte
		ipSrc string
		ipDst string
	)

	defer wg.Done()

	copy(src[:], key.Addrs.Src.In6U.U6Addr8[:])
	copy(dst[:], key.Addrs.Dst.In6U.U6Addr8[:])

	if key.Flags&FLAG_SRC_I == FLAG_SRC_I {
		srcIdx := binary.LittleEndian.Uint32(key.Addrs.Src.In6U.U6Addr8[0:4])
		ipSrc = IpRanges[srcIdx].Name
	} else {
		ipSrc = netip.AddrFrom16(src).String()
	}

	if key.Flags&FLAG_DST_I == FLAG_DST_I {
		dstIdx := binary.LittleEndian.Uint32(key.Addrs.Src.In6U.U6Addr8[0:4])
		ipDst = IpRanges[dstIdx].Name
	} else {
		ipDst = netip.AddrFrom16(dst).String()
	}

	ch <- prometheus.MustNewConstMetric(c.trafficMon6CapturedBytes, prometheus.CounterValue, float64(val.Bytes), ipSrc, ipDst)
}

func processCounters(c *trafficmonCollector, ch chan<- prometheus.Metric) {
	mu.Lock()
	defer mu.Unlock()

	var (
		key    cntIp4PairAddrKey
		aggKey cntIp4PairAddrValue
		val    cntIp4PairValue

		key6    cntIp6PairAddrKey
		aggKey6 cntIp6PairAddrValue
		val6    cntIp6PairValue

		wg sync.WaitGroup
	)

	iter := objs.Ip4Packets.Iterate()

	for iter.Next(&key, &val) {
		wg.Add(1)
		go handleIp4Pair(&wg, c, ch, key, val)
	}

	iterAgg := objs.Ip4PacketsAgg.Iterate()

	for iterAgg.Next(&aggKey, &val) {
		wg.Add(1)
		go hadnleIP4PairAgg(&wg, c, ch, aggKey, val)
	}

	iter6 := objs.Ip6Packets.Iterate()

	for iter6.Next(&key6, &val6) {
		wg.Add(1)
		go handleIp6Pair(&wg, c, ch, key6, val6)
	}

	iterAgg6 := objs.Ip6PacketsAgg.Iterate()

	for iterAgg6.Next(&aggKey6, &val6) {
		wg.Add(1)
		go hadnleIP6PairAgg(&wg, c, ch, aggKey6, val6)
	}

	wg.Wait()
}

func cleanUpStaleMetrics() {
	var (
		keyAgg cntIp4PairAddrValue
		key    cntIp4PairAddrKey
		val    cntIp4PairValue

		keyAgg6 cntIp6PairAddrValue
		key6    cntIp6PairAddrKey
		val6    cntIp6PairValue
	)

	mu.Lock()
	defer mu.Unlock()

	logrus.Info("Cleanup stale metrics: start")

	cutoff := uint64(nanotime()) - 3e11 // 5 minutes

	// Cleanup ip4 metrics
	iter := objs.Ip4Packets.Iterate()

	keys := make([]cntIp4PairAddrKey, 0)
	for iter.Next(&key, &val) {
		if val.Ts < cutoff {
			keys = append(keys, key)
		}
	}
	objs.Ip4Packets.BatchDelete(keys, nil)

	// Cleanup ip4 agg metrics
	iterAgg := objs.Ip4PacketsAgg.Iterate()

	keysAgg := make([]cntIp4PairAddrValue, 0)
	for iterAgg.Next(&keyAgg, &val) {
		if val.Ts < cutoff {
			keysAgg = append(keysAgg, keyAgg)
		}
	}
	objs.Ip4PacketsAgg.BatchDelete(keysAgg, nil)

	// Cleanup ip6 metrics
	iter6 := objs.Ip6Packets.Iterate()

	keys6 := make([]cntIp6PairAddrKey, 0)
	for iter6.Next(&key6, &val6) {
		if val.Ts < cutoff {
			keys6 = append(keys6, key6)
		}
	}
	objs.Ip6Packets.BatchDelete(keys6, nil)

	// Cleanup ip6 agg metrics
	iterAgg6 := objs.Ip6PacketsAgg.Iterate()

	keysAgg6 := make([]cntIp6PairAddrValue, 0)
	for iterAgg6.Next(&keyAgg6, &val6) {
		if val.Ts < cutoff {
			keysAgg6 = append(keysAgg6, keyAgg6)
		}
	}
	objs.Ip6PacketsAgg.BatchDelete(keysAgg6, nil)

	logrus.Info("Cleanup stale metrics: done")
}
