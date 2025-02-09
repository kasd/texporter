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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir ./cmd/texporter -type ip4_pair_addr_key -type ip4_pair_addr_value -type ip6_pair_addr_key -type ip6_pair_addr_value cnt cmd/texporter/cnt.c
