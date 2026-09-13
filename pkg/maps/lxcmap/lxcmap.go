// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	eptypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

const (
	mapName = "cilium_lxc"

	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65535
)

// Map provides access to the endpoints (lxc) eBPF map.
type Map interface {
	// WriteEndpoint updates the BPF map with the endpoint information and links
	// the endpoint information to all keys provided.
	WriteEndpoint(f EndpointFrontend) error

	// SyncHostEntry checks if a host entry exists in the lxcmap and adds one if needed.
	// Returns boolean indicating if a new entry was added and an error.
	SyncHostEntry(addr netip.Addr) (bool, error)

	// DeleteEntry deletes a single map entry
	DeleteEntry(addr netip.Addr) error

	// DeleteElement deletes the endpoint using all keys which represent the
	// endpoint. It returns the number of errors encountered during deletion.
	DeleteElement(logger *slog.Logger, f EndpointFrontend) []error

	// Dump returns the map (type map[string][]string) which contains all
	// data stored in BPF map.
	Dump(hash map[string][]string) error

	// DumpToMap dumps the contents of the lxcmap into a map and returns it
	DumpToMap() (map[netip.Addr]EndpointInfo, error)
}

type lxcMap struct {
	bpfMap *bpf.Map
}

func newMap(registry *metrics.Registry) *lxcMap {
	return &lxcMap{
		bpfMap: bpf.NewMap(mapName,
			ebpf.Hash,
			&EndpointKey{},
			&EndpointInfo{},
			MaxEntries,
			unix.BPF_F_RDONLY_PROG,
		).
			WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(mapName)),
	}
}

// OpenMap opens the pre-initialized LXC map for access.
// This should only be used from components which aren't capable of using hive - mainly the cilium-dbg.
// It needs to initialized beforehand via the Cilium Agent.
func OpenMap(logger *slog.Logger) (Map, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, mapName), &EndpointKey{}, &EndpointInfo{})
	if err != nil {
		return nil, fmt.Errorf("failed to open map: %w", err)
	}

	return &lxcMap{bpfMap: m}, nil
}

func (m *lxcMap) init() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *lxcMap) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}

const (
	// EndpointFlagHost indicates that this endpoint represents the host
	EndpointFlagHost = 1

	// EndpointFlagAtHostNS indicates that this endpoint is located at the host networking
	// namespace
	EndpointFlagAtHostNS = 2

	// EndpointFlagSkipMasqueradeV4 indicates that this endpoint should skip IPv4 masquerade for remote traffic
	EndpointFlagSkipMasqueradeV4 = 4

	// EndpointFlagSkipMasqueradeV6 indicates that this endpoint should skip IPv6 masquerade for remote traffic
	EndpointFlagSkipMasqueradeV6 = 8
)

// EndpointFrontend is the interface to implement for an object to synchronize
// with the endpoint BPF map.
type EndpointFrontend interface {
	LXCMac() mac.MAC
	GetNodeMAC() mac.MAC
	GetIfIndex() int
	GetParentIfIndex() int
	GetID() uint64
	GetRTInfo() (uint32, eptypes.RTInfoEncoding)
	IPv4Address() netip.Addr
	IPv6Address() netip.Addr
	GetIdentity() identity.NumericIdentity
	IsAtHostNS() bool
	// SkipMasqueradeV4 indicates whether this endpoint should skip IPv4 masquerade for remote traffic
	SkipMasqueradeV4() bool
	// SkipMasqueradeV6 indicates whether this endpoint should skip IPv6 masquerade for remote traffic
	SkipMasqueradeV6() bool
}

// getBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map
func (m *lxcMap) getBPFKeys(e EndpointFrontend) []*EndpointKey {
	keys := make([]*EndpointKey, 0, 2)
	if e.IPv6Address().IsValid() {
		keys = append(keys, newEndpointKey(e.IPv6Address()))
	}

	if e.IPv4Address().IsValid() {
		keys = append(keys, newEndpointKey(e.IPv4Address()))
	}

	return keys
}

// getBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
// Must only be called if init() succeeded.
func (m *lxcMap) getBPFValue(e EndpointFrontend) (*EndpointInfo, error) {
	rtInfo, _ := e.GetRTInfo()
	// Both lxc and node mac can be unset for the case of L3/NOARP devices, in
	// which case they are written to the map as zero.
	info := &EndpointInfo{
		IfIndex:       uint32(e.GetIfIndex()),
		LxcID:         uint16(e.GetID()),
		MAC:           e.LXCMac(),
		NodeMAC:       e.GetNodeMAC(),
		SecID:         e.GetIdentity().Uint32(), // Host byte-order
		ParentIfIndex: uint32(e.GetParentIfIndex()),
		RTInfo:        rtInfo,
	}

	if e.IsAtHostNS() {
		info.Flags |= EndpointFlagAtHostNS
	}
	if e.SkipMasqueradeV4() {
		info.Flags |= EndpointFlagSkipMasqueradeV4
	}
	if e.SkipMasqueradeV6() {
		info.Flags |= EndpointFlagSkipMasqueradeV6
	}

	return info, nil
}

type pad2uint32 [2]uint32

// EndpointInfo represents the value of the endpoints BPF map.
//
// Must be in sync with struct endpoint_info in <bpf/lib/eps.h>
type EndpointInfo struct {
	IfIndex       uint32  `align:"ifindex"`
	Unused        uint16  `align:"unused"`
	LxcID         uint16  `align:"lxc_id"`
	Flags         uint32  `align:"flags"`
	RTInfo        uint32  `align:"rt_info"`
	MAC           mac.MAC `align:"mac"`
	_             [2]byte
	NodeMAC       mac.MAC `align:"node_mac"`
	_             [2]byte
	SecID         uint32     `align:"sec_id"`
	ParentIfIndex uint32     `align:"parent_ifindex"`
	Pad           pad2uint32 `align:"pad"`
}

type EndpointKey struct {
	bpf.EndpointKey
}

// newEndpointKey returns an EndpointKey based on the provided IP address. The
// address family is automatically detected
func newEndpointKey(addr netip.Addr) *EndpointKey {
	return &EndpointKey{
		EndpointKey: bpf.NewEndpointKey(addr, 0),
	}
}

func (k *EndpointKey) New() bpf.MapKey { return &EndpointKey{} }

// IsHost returns true if the EndpointInfo represents a host IP
func (v *EndpointInfo) IsHost() bool {
	return v.Flags&EndpointFlagHost != 0
}

const hexUpper = "0123456789ABCDEF"

func appendLeftPad(b []byte, n uint64, width int) []byte {
	start := len(b)
	b = strconv.AppendUint(b, n, 10)
	written := len(b) - start
	for i := written; i < width; i++ {
		b = append(b, ' ')
	}
	return b
}

func appendHex4(b []byte, v uint32) []byte {
	return append(b,
		hexUpper[(v>>12)&0xf],
		hexUpper[(v>>8)&0xf],
		hexUpper[(v>>4)&0xf],
		hexUpper[v&0xf],
	)
}

// String returns the human readable representation of an EndpointInfo
func (v *EndpointInfo) String() string {
	if v.Flags&EndpointFlagHost != 0 {
		return "(localhost)"
	}

	var buf [160]byte
	b := append(buf[:0], "id="...)
	b = appendLeftPad(b, uint64(v.LxcID), 5)
	b = append(b, " sec_id="...)
	b = appendLeftPad(b, uint64(v.SecID), 5)
	b = append(b, " flags=0x"...)
	b = appendHex4(b, v.Flags)
	b = append(b, " ifindex="...)
	b = appendLeftPad(b, uint64(v.IfIndex), 3)
	b = append(b, " mac="...)
	b = v.MAC.AppendTo(b)
	b = append(b, " nodemac="...)
	b = v.NodeMAC.AppendTo(b)
	b = append(b, " parent_ifindex="...)
	b = appendLeftPad(b, uint64(v.ParentIfIndex), 3)
	b = append(b, " rt_info:"...)
	b = strconv.AppendUint(b, uint64(v.RTInfo), 10)
	return string(b)
}

func (v *EndpointInfo) New() bpf.MapValue { return &EndpointInfo{} }

func (m *lxcMap) WriteEndpoint(f EndpointFrontend) error {
	info, err := m.getBPFValue(f)
	if err != nil {
		return err
	}

	var keys [2]EndpointKey
	var numKeys int
	if v6 := f.IPv6Address(); v6.IsValid() {
		keys[numKeys] = EndpointKey{EndpointKey: bpf.NewEndpointKey(v6, 0)}
		numKeys++
	}
	if v4 := f.IPv4Address(); v4.IsValid() {
		keys[numKeys] = EndpointKey{EndpointKey: bpf.NewEndpointKey(v4, 0)}
		numKeys++
	}

	for i := 0; i < numKeys; i++ {
		if err := m.bpfMap.Update(&keys[i], info); err != nil {
			for j := 0; j < i; j++ {
				_ = m.bpfMap.Delete(&keys[j])
			}
			return fmt.Errorf("failed to update key %v in LXC map: %w", &keys[i], err)
		}
	}

	return nil
}

// addHostEntry adds a special endpoint which represents the local host
func (m *lxcMap) addHostEntry(addr netip.Addr) error {
	key := EndpointKey{EndpointKey: bpf.NewEndpointKey(addr, 0)}
	ep := &EndpointInfo{Flags: EndpointFlagHost}
	return m.bpfMap.Update(&key, ep)
}

func (m *lxcMap) SyncHostEntry(addr netip.Addr) (bool, error) {
	key := EndpointKey{EndpointKey: bpf.NewEndpointKey(addr, 0)}
	value, err := m.bpfMap.Lookup(&key)
	if err != nil || value.(*EndpointInfo).Flags&EndpointFlagHost == 0 {
		err = m.addHostEntry(addr)
		if err == nil {
			return true, nil
		}
	}
	return false, err
}

func (m *lxcMap) DeleteEntry(addr netip.Addr) error {
	key := EndpointKey{EndpointKey: bpf.NewEndpointKey(addr, 0)}
	return m.bpfMap.Delete(&key)
}

func (m *lxcMap) DeleteElement(logger *slog.Logger, f EndpointFrontend) []error {
	var errors []error
	if v6 := f.IPv6Address(); v6.IsValid() {
		k := EndpointKey{EndpointKey: bpf.NewEndpointKey(v6, 0)}
		if err := m.bpfMap.Delete(&k); err != nil {
			errors = append(errors, fmt.Errorf("unable to delete key %v from %s: %w", &k, bpf.MapPath(logger, mapName), err))
		}
	}
	if v4 := f.IPv4Address(); v4.IsValid() {
		k := EndpointKey{EndpointKey: bpf.NewEndpointKey(v4, 0)}
		if err := m.bpfMap.Delete(&k); err != nil {
			errors = append(errors, fmt.Errorf("unable to delete key %v from %s: %w", &k, bpf.MapPath(logger, mapName), err))
		}
	}

	return errors
}

func (m *lxcMap) Dump(hash map[string][]string) error {
	return m.bpfMap.Dump(hash)
}

func (m *lxcMap) DumpToMap() (map[netip.Addr]EndpointInfo, error) {
	result := map[netip.Addr]EndpointInfo{}
	callback := func(key bpf.MapKey, value bpf.MapValue) {
		if info, ok := value.(*EndpointInfo); ok {
			if endpointKey, ok := key.(*EndpointKey); ok {
				result[endpointKey.ToAddr()] = *info
			}
		}
	}

	if err := m.bpfMap.DumpWithCallback(callback); err != nil {
		return nil, fmt.Errorf("unable to read BPF endpoint list: %w", err)
	}

	return result, nil
}
