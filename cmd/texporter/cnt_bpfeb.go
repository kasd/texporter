// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type cntIp4LpmTrieKey struct {
	LpmKey struct {
		Prefixlen uint32
		Data      [0]uint8
	}
	Addr uint32
}

type cntIp4PairAddrKey struct {
	Src uint32
	Dst uint32
}

type cntIp4PairAddrValue struct {
	Flags uint8
	Addrs cntIp4PairAddrKey
}

type cntIp4PairValue struct {
	Bytes uint64
	Ts    uint64
}

type cntIp6LpmTrieKey struct {
	LpmKey struct {
		Prefixlen uint32
		Data      [0]uint8
	}
	Addr struct{ In6U struct{ U6Addr8 [16]uint8 } }
}

type cntIp6PairAddrKey struct {
	Src struct{ In6U struct{ U6Addr8 [16]uint8 } }
	Dst struct{ In6U struct{ U6Addr8 [16]uint8 } }
}

type cntIp6PairAddrValue struct {
	Flags uint8
	Addrs cntIp6PairAddrKey
}

type cntIp6PairValue struct {
	Bytes uint64
	Ts    uint64
}

// loadCnt returns the embedded CollectionSpec for cnt.
func loadCnt() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_CntBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load cnt: %w", err)
	}

	return spec, err
}

// loadCntObjects loads cnt and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*cntObjects
//	*cntPrograms
//	*cntMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadCntObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadCnt()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// cntSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type cntSpecs struct {
	cntProgramSpecs
	cntMapSpecs
}

// cntSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type cntProgramSpecs struct {
	CntTcProgFunc  *ebpf.ProgramSpec `ebpf:"cnt_tc_prog_func"`
	CntXdpProgFunc *ebpf.ProgramSpec `ebpf:"cnt_xdp_prog_func"`
}

// cntMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type cntMapSpecs struct {
	Ip4Address    *ebpf.MapSpec `ebpf:"ip4_address"`
	Ip4LpmTrie    *ebpf.MapSpec `ebpf:"ip4_lpm_trie"`
	Ip4Packets    *ebpf.MapSpec `ebpf:"ip4_packets"`
	Ip4PacketsAgg *ebpf.MapSpec `ebpf:"ip4_packets_agg"`
	Ip6Address    *ebpf.MapSpec `ebpf:"ip6_address"`
	Ip6LpmTrie    *ebpf.MapSpec `ebpf:"ip6_lpm_trie"`
	Ip6Packets    *ebpf.MapSpec `ebpf:"ip6_packets"`
	Ip6PacketsAgg *ebpf.MapSpec `ebpf:"ip6_packets_agg"`
}

// cntObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadCntObjects or ebpf.CollectionSpec.LoadAndAssign.
type cntObjects struct {
	cntPrograms
	cntMaps
}

func (o *cntObjects) Close() error {
	return _CntClose(
		&o.cntPrograms,
		&o.cntMaps,
	)
}

// cntMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadCntObjects or ebpf.CollectionSpec.LoadAndAssign.
type cntMaps struct {
	Ip4Address    *ebpf.Map `ebpf:"ip4_address"`
	Ip4LpmTrie    *ebpf.Map `ebpf:"ip4_lpm_trie"`
	Ip4Packets    *ebpf.Map `ebpf:"ip4_packets"`
	Ip4PacketsAgg *ebpf.Map `ebpf:"ip4_packets_agg"`
	Ip6Address    *ebpf.Map `ebpf:"ip6_address"`
	Ip6LpmTrie    *ebpf.Map `ebpf:"ip6_lpm_trie"`
	Ip6Packets    *ebpf.Map `ebpf:"ip6_packets"`
	Ip6PacketsAgg *ebpf.Map `ebpf:"ip6_packets_agg"`
}

func (m *cntMaps) Close() error {
	return _CntClose(
		m.Ip4Address,
		m.Ip4LpmTrie,
		m.Ip4Packets,
		m.Ip4PacketsAgg,
		m.Ip6Address,
		m.Ip6LpmTrie,
		m.Ip6Packets,
		m.Ip6PacketsAgg,
	)
}

// cntPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadCntObjects or ebpf.CollectionSpec.LoadAndAssign.
type cntPrograms struct {
	CntTcProgFunc  *ebpf.Program `ebpf:"cnt_tc_prog_func"`
	CntXdpProgFunc *ebpf.Program `ebpf:"cnt_xdp_prog_func"`
}

func (p *cntPrograms) Close() error {
	return _CntClose(
		p.CntTcProgFunc,
		p.CntXdpProgFunc,
	)
}

func _CntClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed cnt_bpfeb.o
var _CntBytes []byte
