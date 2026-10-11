// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	runtime_client "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	clientapi "github.com/cilium/cilium/api/v1/health/client"
	"github.com/cilium/cilium/api/v1/health/client/connectivity"
	"github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/pkg/health/defaults"
)

type ConnectivityStatusType int

const (
	ipUnavailable = "Unavailable"

	ConnStatusReachable   ConnectivityStatusType = 0
	ConnStatusUnreachable ConnectivityStatusType = 1
	ConnStatusUnknown     ConnectivityStatusType = 2
)

func (c ConnectivityStatusType) String() string {
	switch c {
	case ConnStatusReachable:
		return "reachable"
	case ConnStatusUnreachable:
		return "unreachable"
	default:
		return "unknown"
	}
}

// Client is a client for cilium health
type Client struct {
	clientapi.CiliumHealthAPI
}

func configureTransport(tr *http.Transport, proto, addr string) *http.Transport {
	if tr == nil {
		tr = &http.Transport{}
	}

	if proto == "unix" {
		// No need for compression in local communications.
		tr.DisableCompression = true
		tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial(proto, addr)
		}
	} else {
		tr.Proxy = http.ProxyFromEnvironment
		tr.DialContext = (&net.Dialer{}).DialContext
	}

	return tr
}

// NewDefaultClient creates a client with default parameters connecting to UNIX domain socket.
func NewDefaultClient() (*Client, error) {
	return NewClient("")
}

// NewClient creates a client for the given `host`.
func NewClient(host string) (*Client, error) {
	if host == "" {
		// Check if environment variable points to socket
		e := os.Getenv(defaults.SockPathEnv)
		if e == "" {
			// If unset, fall back to default value
			e = defaults.SockPath
		}
		host = "unix://" + e
	}
	tmp := strings.SplitN(host, "://", 2)
	if len(tmp) != 2 {
		return nil, fmt.Errorf("invalid host format '%s'", host)
	}

	hostHeader := tmp[1]

	switch tmp[0] {
	case "tcp":
		if _, err := url.Parse("tcp://" + tmp[1]); err != nil {
			return nil, err
		}
		host = "http://" + tmp[1]
	case "unix":
		host = tmp[1]
		// For local communication (unix domain sockets), the hostname is not used. Leave
		// Host header empty because otherwise it would be rejected by net/http client-side
		// sanitization, see https://go.dev/issue/60374.
		hostHeader = "localhost"
	}

	transport := configureTransport(nil, tmp[0], host)
	httpClient := &http.Client{Transport: transport}
	clientTrans := runtime_client.NewWithClient(hostHeader, clientapi.DefaultBasePath,
		clientapi.DefaultSchemes, httpClient)
	return &Client{*clientapi.New(clientTrans, strfmt.Default)}, nil
}

// Hint tries to improve the error message displayed to the user.
func Hint(err error) error {
	if err == nil {
		return err
	}
	e, _ := url.PathUnescape(err.Error())
	if strings.Contains(err.Error(), defaults.SockPath) {
		return fmt.Errorf("%s\nIs the agent running?", e)
	}
	return fmt.Errorf("%s", e)
}

func GetConnectivityStatusType(cs *models.ConnectivityStatus) ConnectivityStatusType {
	// If the connecticity status is nil, it means that there was no
	// successful probe, but also no failed probe with a concrete reason. In
	// that case, the status is unknown and it usually means that the new
	// is still in the beginning of the bootstraping process.
	if cs == nil {
		return ConnStatusUnknown
	}
	// Empty status means successful probe.
	if cs.Status == "" {
		return ConnStatusReachable
	}
	// Non-empty status means that there was an explicit reason of failure.
	return ConnStatusUnreachable
}

func GetPathConnectivityStatusType(cp *models.PathStatus) ConnectivityStatusType {
	if cp == nil {
		return ConnStatusUnreachable
	}
	statuses := []*models.ConnectivityStatus{
		cp.Icmp,
		cp.HTTP,
	}
	// Initially assume healthy status.
	status := ConnStatusReachable
	for _, cs := range statuses {
		switch GetConnectivityStatusType(cs) {
		case ConnStatusUnreachable:
			// If any status is unreachable, return it immediately.
			return ConnStatusUnreachable
		case ConnStatusUnknown:
			// If the status is unknown, prepare to return it. It's
			// going to be returned if there is no unreachable
			// status in next iterations.
			status = ConnStatusUnknown
		}
	}
	return status
}

// Returns a map of ConnectivityStatusType --> # of paths with ConnectivityStatusType
func SummarizePathConnectivityStatusType(cps []*models.PathStatus) map[ConnectivityStatusType]int {
	status := make(map[ConnectivityStatusType]int)
	for _, cp := range cps {
		cst := GetPathConnectivityStatusType(cp)
		status[cst]++
	}
	return status
}

func summarizeNodePaths(hasParent bool, primary *models.PathStatus, secondaries []*models.PathStatus) (reachable, unknown, total int, healthy bool) {
	healthy = true
	if !hasParent {
		return
	}
	total = 1 + len(secondaries)
	switch GetPathConnectivityStatusType(primary) {
	case ConnStatusReachable:
		reachable++
	case ConnStatusUnknown:
		unknown++
	case ConnStatusUnreachable:
		healthy = false
	}
	for _, addr := range secondaries {
		switch GetPathConnectivityStatusType(addr) {
		case ConnStatusReachable:
			reachable++
		case ConnStatusUnknown:
			unknown++
		case ConnStatusUnreachable:
			healthy = false
		}
	}
	return
}

var durationBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 32)
		return &b
	},
}

var pow10 = [...]uint64{
	1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000,
}

func appendDuration(buf []byte, d time.Duration) []byte {
	if d == 0 {
		return append(buf, "0s"...)
	}

	u := uint64(d)
	if d < 0 {
		buf = append(buf, '-')
		u = -u
	}

	if u < uint64(time.Second) {
		var unit string
		var divisor uint64
		var prec int

		if u < uint64(time.Microsecond) {
			buf = strconv.AppendUint(buf, u, 10)
			return append(buf, "ns"...)
		} else if u < uint64(time.Millisecond) {
			unit = "µs"
			divisor = uint64(time.Microsecond)
			prec = 3
		} else {
			unit = "ms"
			divisor = uint64(time.Millisecond)
			prec = 6
		}

		buf = strconv.AppendUint(buf, u/divisor, 10)
		frac := u % divisor
		if frac > 0 {
			buf = append(buf, '.')
			for frac%10 == 0 {
				frac /= 10
				prec--
			}
			for i := prec - 1; i > 0; i-- {
				if frac < pow10[i] {
					buf = append(buf, '0')
				} else {
					break
				}
			}
			buf = strconv.AppendUint(buf, frac, 10)
		}
		return append(buf, unit...)
	}

	if u >= uint64(time.Hour) {
		buf = strconv.AppendUint(buf, u/uint64(time.Hour), 10)
		buf = append(buf, 'h')
		u %= uint64(time.Hour)
		buf = strconv.AppendUint(buf, u/uint64(time.Minute), 10)
		buf = append(buf, 'm')
		u %= uint64(time.Minute)
	} else if u >= uint64(time.Minute) {
		buf = strconv.AppendUint(buf, u/uint64(time.Minute), 10)
		buf = append(buf, 'm')
		u %= uint64(time.Minute)
	}

	buf = strconv.AppendUint(buf, u/uint64(time.Second), 10)
	frac := u % uint64(time.Second)
	if frac > 0 {
		buf = append(buf, '.')
		prec := 9
		for frac%10 == 0 {
			frac /= 10
			prec--
		}
		for i := prec - 1; i > 0; i-- {
			if frac < pow10[i] {
				buf = append(buf, '0')
			} else {
				break
			}
		}
		buf = strconv.AppendUint(buf, frac, 10)
	}
	buf = append(buf, 's')

	return buf
}

func writeDuration(w io.Writer, d time.Duration) {
	bufPtr := durationBufPool.Get().(*[]byte)
	buf := appendDuration((*bufPtr)[:0], d)
	w.Write(buf)
	if cap(buf) <= 64 {
		*bufPtr = buf[:0]
		durationBufPool.Put(bufPtr)
	}
}

func formatConnectivityStatus(w io.Writer, cs *models.ConnectivityStatus, path, indent, subIndent string) {
	io.WriteString(w, indent)
	io.WriteString(w, subIndent)
	io.WriteString(w, path)
	io.WriteString(w, ":\t")
	if GetConnectivityStatusType(cs) == ConnStatusReachable {
		io.WriteString(w, "OK, RTT=")
		writeDuration(w, time.Duration(cs.Latency))
	} else {
		io.WriteString(w, cs.Status)
	}
	io.WriteString(w, "\t(Last probed: ")
	io.WriteString(w, cs.LastProbed)
	io.WriteString(w, ")\n")
}

func formatPathStatus(w io.Writer, name string, cp *models.PathStatus, indent string, verbose bool) {
	if cp == nil {
		if verbose {
			io.WriteString(w, indent)
			io.WriteString(w, name)
			io.WriteString(w, " connectivity:\tnil\n")
		}
		return
	}
	io.WriteString(w, indent)
	io.WriteString(w, name)
	io.WriteString(w, " connectivity to ")
	io.WriteString(w, cp.IP)
	io.WriteString(w, ":\n")

	if cp.Icmp != nil {
		formatConnectivityStatus(w, cp.Icmp, "ICMP to stack", indent, "  ")
	}
	if cp.HTTP != nil {
		formatConnectivityStatus(w, cp.HTTP, "HTTP to agent", indent, "  ")
	}
}

// allPathsAreHealthyOrUnknown checks whether ICMP and TCP(HTTP) connectivity
// to the given paths is available or had no explicit error status
// (which usually is the case when the new node is provisioned).
func allPathsAreHealthyOrUnknown(cps []*models.PathStatus) bool {
	for _, cp := range cps {
		if cp == nil {
			return false
		}

		statuses := []*models.ConnectivityStatus{
			cp.Icmp,
			cp.HTTP,
		}
		for _, status := range statuses {
			switch GetConnectivityStatusType(status) {
			case ConnStatusUnreachable:
				return false
			}
		}
	}
	return true
}

func nodeIsHealthy(node *models.NodeStatus) bool {
	_, _, _, hostHealthy := summarizeNodePaths(node.Host != nil, GetHostPrimaryAddress(node), GetHostSecondaryAddresses(node))
	_, _, _, epHealthy := summarizeNodePaths(node.HealthEndpoint != nil, GetEndpointPrimaryAddress(node), GetEndpointSecondaryAddresses(node))
	return hostHealthy && epHealthy
}

func nodeIsLocalhost(node *models.NodeStatus, self *models.SelfStatus) bool {
	return self != nil && node.Name == self.Name
}

func getPrimaryAddressIP(node *models.NodeStatus) string {
	if node.Host == nil || node.Host.PrimaryAddress == nil {
		return ipUnavailable
	}

	return node.Host.PrimaryAddress.IP
}

// GetHostPrimaryAddress returns the PrimaryAddress for the Host within node.
// If node.Host is nil, returns nil.
func GetHostPrimaryAddress(node *models.NodeStatus) *models.PathStatus {
	if node.Host == nil {
		return nil
	}

	return node.Host.PrimaryAddress
}

// GetHostSecondaryAddresses returns the secondary host addresses (if any)
func GetHostSecondaryAddresses(node *models.NodeStatus) []*models.PathStatus {
	if node.Host == nil {
		return nil
	}

	return node.Host.SecondaryAddresses
}

// GetAllHostAddresses returns a list of all addresses (primary and any
// and any secondary) for the host of a given node. If node.Host is nil,
// returns nil.
func GetAllHostAddresses(node *models.NodeStatus) []*models.PathStatus {
	if node.Host == nil {
		return nil
	}

	return append([]*models.PathStatus{node.Host.PrimaryAddress}, node.Host.SecondaryAddresses...)
}

// GetEndpointPrimaryAddress returns the PrimaryAddress for the health endpoint
// within node. If node.HealthEndpoint is nil, returns nil.
func GetEndpointPrimaryAddress(node *models.NodeStatus) *models.PathStatus {
	if node.HealthEndpoint == nil {
		return nil
	}

	return node.HealthEndpoint.PrimaryAddress
}

// GetEndpointSecondaryAddresses returns the secondary health endpoint addresses
// (if any)
func GetEndpointSecondaryAddresses(node *models.NodeStatus) []*models.PathStatus {
	if node.HealthEndpoint == nil {
		return nil
	}

	return node.HealthEndpoint.SecondaryAddresses
}

// GetAllEndpointAddresses returns a list of all addresses (primary and any
// secondary) for the health endpoint within a given node.
// If node.HealthEndpoint is nil, returns nil.
func GetAllEndpointAddresses(node *models.NodeStatus) []*models.PathStatus {
	if node.HealthEndpoint == nil {
		return nil
	}

	return append([]*models.PathStatus{node.HealthEndpoint.PrimaryAddress}, node.HealthEndpoint.SecondaryAddresses...)
}

func formatNodeStatus(w io.Writer, node *models.NodeStatus, allNodes, verbose, localhost bool) bool {
	localStr := ""
	if localhost {
		localStr = " (localhost)"
	}

	if verbose {
		io.WriteString(w, "  ")
		io.WriteString(w, node.Name)
		io.WriteString(w, localStr)
		io.WriteString(w, ":\n")
		formatPathStatus(w, "Host", GetHostPrimaryAddress(node), "    ", verbose)
		if node.Host != nil {
			for _, addr := range node.Host.SecondaryAddresses {
				formatPathStatus(w, "Secondary Host", addr, "    ", verbose)
			}
		}
		formatPathStatus(w, "Endpoint", GetEndpointPrimaryAddress(node), "    ", verbose)
		if node.HealthEndpoint != nil {
			for _, addr := range node.HealthEndpoint.SecondaryAddresses {
				formatPathStatus(w, "Secondary Endpoint", addr, "    ", verbose)
			}
		}
		return true
	}

	hostReachable, hostUnknown, hostTotal, hostHealthy := summarizeNodePaths(node.Host != nil, GetHostPrimaryAddress(node), GetHostSecondaryAddresses(node))
	epReachable, epUnknown, epTotal, epHealthy := summarizeNodePaths(node.HealthEndpoint != nil, GetEndpointPrimaryAddress(node), GetEndpointSecondaryAddresses(node))
	nodeHealthy := hostHealthy && epHealthy

	if !nodeHealthy || allNodes {
		io.WriteString(w, "  ")
		io.WriteString(w, node.Name)
		io.WriteString(w, localStr)
		io.WriteString(w, "\t")
		io.WriteString(w, getPrimaryAddressIP(node))
		for _, addr := range GetHostSecondaryAddresses(node) {
			if addr == nil {
				continue
			}
			io.WriteString(w, ",")
			io.WriteString(w, addr.IP)
		}
		io.WriteString(w, "\t")
		io.WriteString(w, strconv.Itoa(hostReachable))
		io.WriteString(w, "/")
		io.WriteString(w, strconv.Itoa(hostTotal))
		if hostUnknown > 0 {
			io.WriteString(w, " (")
			io.WriteString(w, strconv.Itoa(hostUnknown))
			io.WriteString(w, " unknown)")
		}
		io.WriteString(w, "\t")
		io.WriteString(w, strconv.Itoa(epReachable))
		io.WriteString(w, "/")
		io.WriteString(w, strconv.Itoa(epTotal))
		if epUnknown > 0 {
			io.WriteString(w, " (")
			io.WriteString(w, strconv.Itoa(epUnknown))
			io.WriteString(w, " unknown)")
		}
		io.WriteString(w, "\n")
		return true
	}

	return false
}

// FormatHealthStatusResponse writes a HealthStatusResponse as a string to the
// writer.
//
// 'allNodes', if true, causes all nodes to be printed regardless of status
// 'verbose', if true, prints all information
// 'maxLines', if nonzero, determines the maximum number of lines to print
func FormatHealthStatusResponse(w io.Writer, sr *models.HealthStatusResponse, allNodes bool, verbose bool, maxLines int) {
	var (
		healthy      int
		localhost    *models.NodeStatus
		printedLines int
	)
	for _, node := range sr.Nodes {
		if nodeIsHealthy(node) {
			healthy++
		}
		if nodeIsLocalhost(node, sr.Local) {
			localhost = node
		}
	}

	fmt.Fprintf(w, "Cluster health:\t%d/%d reachable\t(%s)\t(Probe interval: %s)\n",
		healthy, len(sr.Nodes), sr.Timestamp, sr.ProbeInterval)

	fmt.Fprintf(w, "Name\tIP\tNode\tEndpoints\n")

	if localhost != nil {
		if formatNodeStatus(w, localhost, allNodes, verbose, true) {
			printedLines++
		}
	}

	nodes := sr.Nodes
	sort.Slice(nodes, func(i, j int) bool {
		return strings.Compare(nodes[i].Name, nodes[j].Name) < 0
	})
	for _, node := range nodes {
		if printedLines == maxLines {
			break
		}
		if node == localhost {
			continue
		}
		if formatNodeStatus(w, node, allNodes, verbose, false) {
			printedLines++
		}
	}
	if len(sr.Nodes)-printedLines-healthy > 0 {
		fmt.Fprintf(w, "  ...\n")
	}
}

// GetAndFormatHealthStatus fetches the health status from the cilium-health
// daemon via the default channel and formats its output as a string to the
// writer.
//
// 'verbose' and 'maxLines' are handled the same as in
// FormatHealthStatusResponse().
func GetAndFormatHealthStatus(w io.Writer, allNodes bool, verbose bool, maxLines int) {
	client, err := NewClient("")
	if err != nil {
		fmt.Fprintf(w, "Cluster health:\t\t\tClient error: %s\n", err)
		return
	}
	hr, err := client.Connectivity.GetStatus(connectivity.NewGetStatusParams())
	if err != nil {
		// The regular `cilium status` output will print the reason why.
		fmt.Fprintf(w, "Cluster health:\t\t\tWarning\tcilium-health daemon unreachable\n")
		return
	}
	FormatHealthStatusResponse(w, hr.Payload, allNodes, verbose, maxLines)
}
