// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package threefour

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"go4.org/netipx"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/parser/common"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/correlation"
)

// Parser is a parser for L3/L4 payloads
type Parser struct {
	log            *slog.Logger
	endpointGetter getters.EndpointGetter
	identityGetter getters.IdentityGetter
	dnsGetter      getters.DNSGetter
	ipGetter       getters.IPGetter
	serviceGetter  getters.ServiceGetter
	linkGetter     getters.LinkGetter

	dropNotifyDecoder          options.DropNotifyDecoderFunc
	traceNotifyDecoder         options.TraceNotifyDecoderFunc
	policyVerdictNotifyDecoder options.PolicyVerdictNotifyDecoderFunc
	debugCaptureDecoder        options.DebugCaptureDecoderFunc
	packetDecoder              options.L34PacketDecoder

	epResolver          *common.EndpointResolver
	correlateL3L4Policy bool
}

// re-usable packetDecoder to avoid reallocating gopacket datastructures
type packetDecoder struct {
	lock.Mutex

	decLayerL2Dev *gopacket.DecodingLayerParser
	decLayerL3Dev struct {
		IPv4 *gopacket.DecodingLayerParser
		IPv6 *gopacket.DecodingLayerParser
	}
	decLayerOverlay struct {
		VXLAN  *gopacket.DecodingLayerParser
		Geneve *gopacket.DecodingLayerParser
	}

	Layers []gopacket.LayerType
	layers.Ethernet
	layers.IPv4
	layers.IPv6
	layers.ICMPv4
	layers.ICMPv6
	layers.TCP
	layers.UDP
	layers.SCTP
	layers.VRRPv2
	layers.IGMPv1or2

	overlay struct {
		Layers []gopacket.LayerType
		layers.VXLAN
		layers.Geneve
		layers.Ethernet
		layers.IPv4
		layers.IPv6
		layers.ICMPv4
		layers.ICMPv6
		layers.TCP
		layers.UDP
		layers.SCTP
		layers.VRRPv2
		layers.IGMPv1or2
	}
}

var (
	tcpFlagsStrings   [512]string
	tcpSummaryStrings [512]string
	pbTCPFlagsTable   [512]*pb.TCPFlags

	traceCiliumEventTypes [16]*pb.CiliumEventType

	boolValueTrue  = &wrapperspb.BoolValue{Value: true}
	boolValueFalse = &wrapperspb.BoolValue{Value: false}
)

func init() {
	for m := 0; m < 512; m++ {
		syn := (m & (1 << 0)) != 0
		ack := (m & (1 << 1)) != 0
		rst := (m & (1 << 2)) != 0
		fin := (m & (1 << 3)) != 0
		psh := (m & (1 << 4)) != 0
		urg := (m & (1 << 5)) != 0
		ece := (m & (1 << 6)) != 0
		cwr := (m & (1 << 7)) != 0
		ns := (m & (1 << 8)) != 0

		pbTCPFlagsTable[m] = &pb.TCPFlags{
			FIN: fin, SYN: syn, RST: rst,
			PSH: psh, ACK: ack, URG: urg,
			ECE: ece, CWR: cwr, NS: ns,
		}

		var info []string
		if syn {
			info = append(info, "SYN")
		}
		if ack {
			info = append(info, "ACK")
		}
		if rst {
			info = append(info, "RST")
		}
		if fin {
			info = append(info, "FIN")
		}
		if psh {
			info = append(info, "PSH")
		}
		if urg {
			info = append(info, "URG")
		}
		if ece {
			info = append(info, "ECE")
		}
		if cwr {
			info = append(info, "CWR")
		}
		if ns {
			info = append(info, "NS")
		}

		flagsStr := strings.Join(info, ", ")
		tcpFlagsStrings[m] = flagsStr
		tcpSummaryStrings[m] = "TCP Flags: " + flagsStr
	}

	for subType := 0; subType < len(traceCiliumEventTypes); subType++ {
		traceCiliumEventTypes[subType] = &pb.CiliumEventType{
			Type:    int32(monitorAPI.MessageTypeTrace),
			SubType: int32(subType),
		}
	}
}

func tcpFlagsMask(tcp layers.TCP) int {
	var m int
	if tcp.SYN {
		m |= 1 << 0
	}
	if tcp.ACK {
		m |= 1 << 1
	}
	if tcp.RST {
		m |= 1 << 2
	}
	if tcp.FIN {
		m |= 1 << 3
	}
	if tcp.PSH {
		m |= 1 << 4
	}
	if tcp.URG {
		m |= 1 << 5
	}
	if tcp.ECE {
		m |= 1 << 6
	}
	if tcp.CWR {
		m |= 1 << 7
	}
	if tcp.NS {
		m |= 1 << 8
	}
	return m
}

func boolValue(b bool) *wrapperspb.BoolValue {
	if b {
		return boolValueTrue
	}
	return boolValueFalse
}

const hexDigit = "0123456789abcdef"

func formatMAC(mac net.HardwareAddr) string {
	if len(mac) == 6 {
		var buf [17]byte
		buf[0] = hexDigit[mac[0]>>4]
		buf[1] = hexDigit[mac[0]&0xf]
		buf[2] = ':'
		buf[3] = hexDigit[mac[1]>>4]
		buf[4] = hexDigit[mac[1]&0xf]
		buf[5] = ':'
		buf[6] = hexDigit[mac[2]>>4]
		buf[7] = hexDigit[mac[2]&0xf]
		buf[8] = ':'
		buf[9] = hexDigit[mac[3]>>4]
		buf[10] = hexDigit[mac[3]&0xf]
		buf[11] = ':'
		buf[12] = hexDigit[mac[4]>>4]
		buf[13] = hexDigit[mac[4]&0xf]
		buf[14] = ':'
		buf[15] = hexDigit[mac[5]>>4]
		buf[16] = hexDigit[mac[5]&0xf]
		return string(buf[:])
	}
	return mac.String()
}

// New returns a new L3/L4 parser
func New(
	log *slog.Logger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	linkGetter getters.LinkGetter,
	opts ...options.Option,
) (*Parser, error) {
	packet := &packetDecoder{}
	decoders := []gopacket.DecodingLayer{
		&packet.Ethernet,
		&packet.IPv4, &packet.IPv6,
		&packet.ICMPv4, &packet.ICMPv6,
		&packet.TCP, &packet.UDP, &packet.SCTP,
		&packet.VRRPv2, &packet.IGMPv1or2,
	}
	packet.decLayerL2Dev = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, decoders...)
	packet.decLayerL3Dev.IPv4 = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, decoders...)
	packet.decLayerL3Dev.IPv6 = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, decoders...)

	overlayDecoders := []gopacket.DecodingLayer{
		&packet.overlay.VXLAN, &packet.overlay.Geneve,
		&packet.overlay.Ethernet,
		&packet.overlay.IPv4, &packet.overlay.IPv6,
		&packet.overlay.ICMPv4, &packet.overlay.ICMPv6,
		&packet.overlay.TCP, &packet.overlay.UDP, &packet.overlay.SCTP,
		&packet.overlay.VRRPv2, &packet.overlay.IGMPv1or2,
	}
	packet.decLayerOverlay.VXLAN = gopacket.NewDecodingLayerParser(layers.LayerTypeVXLAN, overlayDecoders...)
	packet.decLayerOverlay.Geneve = gopacket.NewDecodingLayerParser(layers.LayerTypeGeneve, overlayDecoders...)
	// Let packet.decLayer.DecodeLayers return a nil error when it
	// encounters a layer it doesn't have a parser for, instead of returning
	// an UnsupportedLayerType error.
	packet.decLayerL2Dev.IgnoreUnsupported = true
	packet.decLayerL3Dev.IPv4.IgnoreUnsupported = true
	packet.decLayerL3Dev.IPv6.IgnoreUnsupported = true
	packet.decLayerOverlay.VXLAN.IgnoreUnsupported = true
	packet.decLayerOverlay.Geneve.IgnoreUnsupported = true

	args := &options.Options{
		EnableNetworkPolicyCorrelation: true,
		DropNotifyDecoder: func(data []byte, decoded *pb.Flow) (*monitor.DropNotify, error) {
			dn := &monitor.DropNotify{}
			return dn, dn.Decode(data)
		},
		DebugCaptureDecoder: func(data []byte, decoded *pb.Flow) (*monitor.DebugCapture, error) {
			dbg := &monitor.DebugCapture{}
			return dbg, dbg.Decode(data)
		},
		TraceNotifyDecoder: func(data []byte, decoded *pb.Flow) (*monitor.TraceNotify, error) {
			tn := &monitor.TraceNotify{}
			return tn, tn.Decode(data)
		},
		PolicyVerdictNotifyDecoder: func(data []byte, decoded *pb.Flow) (*monitor.PolicyVerdictNotify, error) {
			pvn := &monitor.PolicyVerdictNotify{}
			return pvn, pvn.Decode(data)
		},
		L34PacketDecoder: packet,
	}

	for _, opt := range opts {
		opt(args)
	}

	return &Parser{
		log:                        log,
		dnsGetter:                  dnsGetter,
		endpointGetter:             endpointGetter,
		identityGetter:             identityGetter,
		ipGetter:                   ipGetter,
		serviceGetter:              serviceGetter,
		linkGetter:                 linkGetter,
		dropNotifyDecoder:          args.DropNotifyDecoder,
		debugCaptureDecoder:        args.DebugCaptureDecoder,
		traceNotifyDecoder:         args.TraceNotifyDecoder,
		policyVerdictNotifyDecoder: args.PolicyVerdictNotifyDecoder,
		epResolver:                 common.NewEndpointResolver(log, endpointGetter, identityGetter, ipGetter),
		packetDecoder:              args.L34PacketDecoder,
		correlateL3L4Policy:        args.EnableNetworkPolicyCorrelation,
	}, nil
}

// Decode decodes the data from 'data' into 'decoded'
func (p *Parser) Decode(data []byte, decoded *pb.Flow) error {
	if len(data) == 0 {
		return errors.ErrEmptyData
	}

	eventType := data[0]

	var err error
	var packetOffset int
	var dn *monitor.DropNotify
	var tn *monitor.TraceNotify
	var pvn *monitor.PolicyVerdictNotify
	var dbg *monitor.DebugCapture
	var eventSubType uint8
	var authType pb.AuthType

	switch eventType {
	case monitorAPI.MessageTypeDrop:
		dn, err = p.dropNotifyDecoder(data, decoded)
		if err != nil {
			return fmt.Errorf("failed to parse drop: %w", err)
		}
		eventSubType = dn.SubType
		packetOffset = (int)(dn.DataOffset())
	case monitorAPI.MessageTypeTrace:
		tn, err = p.traceNotifyDecoder(data, decoded)
		if err != nil {
			return fmt.Errorf("failed to parse trace: %w", err)
		}
		eventSubType = tn.ObsPoint

		if tn.ObsPoint != 0 {
			decoded.TraceObservationPoint = pb.TraceObservationPoint(tn.ObsPoint)
		} else {
			// specifically handle the zero value in the observation enum so the json
			// export and the API don't carry extra meaning with the zero value
			decoded.TraceObservationPoint = pb.TraceObservationPoint_TO_ENDPOINT
		}

		packetOffset = (int)(tn.DataOffset())
	case monitorAPI.MessageTypePolicyVerdict:
		pvn, err = p.policyVerdictNotifyDecoder(data, decoded)
		if err != nil {
			return fmt.Errorf("failed to parse policy verdict: %w", err)
		}
		eventSubType = pvn.SubType
		packetOffset = int(pvn.DataOffset())
		authType = pb.AuthType(pvn.GetAuthType())
	case monitorAPI.MessageTypeCapture:
		dbg, err = p.debugCaptureDecoder(data, decoded)
		if err != nil {
			return fmt.Errorf("failed to parse debug capture: %w", err)
		}
		eventSubType = dbg.SubType
		packetOffset = int(dbg.DataOffset())
	default:
		return errors.NewErrInvalidType(eventType)
	}

	if len(data) < packetOffset {
		return fmt.Errorf("not enough bytes to decode %d", data)
	}

	isL3Device := tn != nil && tn.IsL3Device() || dn != nil && dn.IsL3Device() || pvn != nil && pvn.IsTrafficL3Device()
	isIPv6 := tn != nil && tn.IsIPv6() || dn != nil && dn.IsIPv6() || pvn != nil && pvn.IsTrafficIPv6()
	isVXLAN := tn != nil && tn.IsVXLAN() || dn != nil && dn.IsVXLAN()
	isGeneve := tn != nil && tn.IsGeneve() || dn != nil && dn.IsGeneve()
	srcIP, dstIP, srcPort, dstPort, err := p.packetDecoder.DecodePacket(data[packetOffset:], decoded, isL3Device, isIPv6, isVXLAN, isGeneve)
	if err != nil {
		return err
	}

	ip := decoded.GetIP()
	if tn != nil && ip != nil {
		if !tn.OriginalIP().IsUnspecified() {
			srcIP = tn.OriginalIP()
			// On SNAT the trace notification has OrigIP set to the pre
			// translation IP and the source IP parsed from the header is the
			// post translation IP. The check is here because sometimes we get
			// trace notifications with OrigIP set to the header's IP
			// (pre-translation events?)
			srcIPStr := srcIP.String()
			if ip.GetSource() != srcIPStr {
				ip.SourceXlated = ip.GetSource()
				ip.Source = srcIPStr
			}
		}

		ip.Encrypted = tn.IsEncrypted()
	}

	srcLabelID, dstLabelID := decodeSecurityIdentities(dn, tn, pvn)
	datapathContext := common.DatapathContext{
		SrcIP:                 srcIP,
		SrcLabelID:            srcLabelID,
		DstIP:                 dstIP,
		DstLabelID:            dstLabelID,
		TraceObservationPoint: decoded.TraceObservationPoint,
	}
	srcEndpoint := p.epResolver.ResolveEndpoint(srcIP, srcLabelID, datapathContext)
	dstEndpoint := p.epResolver.ResolveEndpoint(dstIP, dstLabelID, datapathContext)
	var sourceService, destinationService *pb.Service
	if p.serviceGetter != nil {
		sourceService = p.serviceGetter.GetServiceByAddr(srcIP, srcPort)
		destinationService = p.serviceGetter.GetServiceByAddr(dstIP, dstPort)
	}

	decoded.Verdict = decodeVerdict(dn, tn, pvn)
	decoded.AuthType = authType
	decoded.DropReason = decodeDropReason(dn, pvn)
	decoded.DropReasonDesc = pb.DropReason(decoded.DropReason)
	decoded.ExtError = decodeExtError(dn)
	decoded.ExtDropReasonDesc = decodeExtDropReasonDesc(dn)
	decoded.File = decodeFileInfo(dn)
	decoded.Source = srcEndpoint
	decoded.Destination = dstEndpoint
	decoded.Type = pb.FlowType_L3_L4
	decoded.SourceNames = p.resolveNames(dstEndpoint.ID, srcIP)
	decoded.DestinationNames = p.resolveNames(srcEndpoint.ID, dstIP)
	decoded.L7 = nil
	decoded.IsReply = decodeIsReply(tn, pvn)
	decoded.Reply = decoded.GetIsReply().GetValue() // false if GetIsReply() is nil
	decoded.TrafficDirection = decodeTrafficDirection(srcEndpoint.ID, dn, tn, pvn)
	decoded.EventType = decodeCiliumEventType(eventType, eventSubType)
	decoded.TraceReason = decodeTraceReason(tn)
	decoded.IpTraceId = decodeIpTraceId(dn, tn)
	decoded.SourceService = sourceService
	decoded.DestinationService = destinationService
	decoded.PolicyMatchType = decodePolicyMatchType(pvn)
	decoded.DebugCapturePoint = decodeDebugCapturePoint(dbg)
	decoded.Interface = p.decodeNetworkInterface(tn, dbg)
	decoded.ProxyPort = decodeProxyPort(dbg, tn)

	if p.correlateL3L4Policy && p.endpointGetter != nil && pvn != nil {
		correlation.CorrelatePolicy(p.log, p.endpointGetter, decoded, pvn.Source)
	}

	return nil
}

func (p *Parser) resolveNames(epID uint32, ip netip.Addr) (names []string) {
	if p.dnsGetter != nil {
		return p.dnsGetter.GetNamesOf(epID, ip)
	}

	return nil
}

func (d *packetDecoder) DecodePacket(payload []byte, decoded *pb.Flow, isL3Device, isIPv6, isVXLAN, isGeneve bool) (
	sourceIP, destinationIP netip.Addr,
	sourcePort, destinationPort uint16,
	err error,
) {
	d.Lock()
	defer d.Unlock()

	// Since v1.1.18, DecodeLayers returns a non-nil error for an empty packet, see
	// https://github.com/google/gopacket/issues/846
	// TODO: reconsider this check if the issue is fixed upstream
	if len(payload) == 0 {
		// Truncate layers to avoid accidental re-use.
		d.Layers = d.Layers[:0]
		d.overlay.Layers = d.overlay.Layers[:0]
		return
	}

	switch {
	case !isL3Device:
		err = d.decLayerL2Dev.DecodeLayers(payload, &d.Layers)
	case isIPv6:
		err = d.decLayerL3Dev.IPv6.DecodeLayers(payload, &d.Layers)
	default:
		err = d.decLayerL3Dev.IPv4.DecodeLayers(payload, &d.Layers)
	}

	if err != nil {
		return
	}

	for _, typ := range d.Layers {
		decoded.Summary = typ.String()
		switch typ {
		case layers.LayerTypeEthernet:
			decoded.Ethernet = decodeEthernet(&d.Ethernet)
		case layers.LayerTypeIPv4:
			decoded.IP, sourceIP, destinationIP = decodeIPv4(&d.IPv4)
		case layers.LayerTypeIPv6:
			decoded.IP, sourceIP, destinationIP = decodeIPv6(&d.IPv6)
		case layers.LayerTypeTCP:
			decoded.L4, sourcePort, destinationPort = decodeTCP(&d.TCP)
			decoded.Summary = getTCPSummary(d.TCP)
		case layers.LayerTypeUDP:
			decoded.L4, sourcePort, destinationPort = decodeUDP(&d.UDP)
		case layers.LayerTypeSCTP:
			decoded.L4, sourcePort, destinationPort = decodeSCTP(&d.SCTP)
		case layers.LayerTypeICMPv4:
			decoded.L4 = decodeICMPv4(&d.ICMPv4)
			decoded.Summary = "ICMPv4 " + d.ICMPv4.TypeCode.String()
		case layers.LayerTypeICMPv6:
			decoded.L4 = decodeICMPv6(&d.ICMPv6)
			decoded.Summary = "ICMPv6 " + d.ICMPv6.TypeCode.String()
		case layers.LayerTypeVRRP:
			decoded.L4 = decodeVRRP(&d.VRRPv2)
			decoded.Summary = "VRRP " + d.VRRPv2.Type.String()
		case layers.LayerTypeIGMP:
			decoded.L4 = decodeIGMP(&d.IGMPv1or2)
			decoded.Summary = "IGMP " + d.IGMPv1or2.Type.String()
		}
	}

	switch {
	case isVXLAN:
		err = d.decLayerOverlay.VXLAN.DecodeLayers(d.UDP.Payload, &d.overlay.Layers)
	case isGeneve:
		err = d.decLayerOverlay.Geneve.DecodeLayers(d.UDP.Payload, &d.overlay.Layers)
	default:
		// Truncate layers to avoid accidental re-use.
		d.overlay.Layers = d.overlay.Layers[:0]
		return
	}

	if err != nil {
		err = fmt.Errorf("overlay: %w", err)
		return
	}

	// Return in case we have not decoded any overlay layer.
	if len(d.overlay.Layers) == 0 {
		return
	}

	// Expect VXLAN/Geneve overlay as first overlay layer, if not we bail out.
	switch d.overlay.Layers[0] {
	case layers.LayerTypeVXLAN:
		decoded.Tunnel = &pb.Tunnel{Protocol: pb.Tunnel_VXLAN, IP: decoded.IP, L4: decoded.L4, Vni: d.overlay.VXLAN.VNI}
	case layers.LayerTypeGeneve:
		decoded.Tunnel = &pb.Tunnel{Protocol: pb.Tunnel_GENEVE, IP: decoded.IP, L4: decoded.L4, Vni: d.overlay.Geneve.VNI}
	default:
		return
	}

	// Reset return values. This ensures the resulting flow does not misrepresent
	// what is happening (e.g. same IP addresses for overlay and underlay).
	decoded.Ethernet, decoded.IP, decoded.L4 = nil, nil, nil
	sourceIP, destinationIP = netip.Addr{}, netip.Addr{}
	sourcePort, destinationPort = 0, 0
	decoded.Summary = ""

	// Parse the rest of the overlay layers as we would do for a non-encapsulated packet.
	// It is possible we're not parsing any layer here. This is because the overlay
	// decoders failed (e.g., not enough data). We would still return empty values
	// for the inner packet (ethernet, ip, l4, basically the re-init variables)
	// while returning the non-empty `tunnel` field.
	for _, typ := range d.overlay.Layers[1:] {
		decoded.Summary = typ.String()
		switch typ {
		case layers.LayerTypeEthernet:
			decoded.Ethernet = decodeEthernet(&d.overlay.Ethernet)
		case layers.LayerTypeIPv4:
			decoded.IP, sourceIP, destinationIP = decodeIPv4(&d.overlay.IPv4)
		case layers.LayerTypeIPv6:
			decoded.IP, sourceIP, destinationIP = decodeIPv6(&d.overlay.IPv6)
		case layers.LayerTypeTCP:
			decoded.L4, sourcePort, destinationPort = decodeTCP(&d.overlay.TCP)
			decoded.Summary = getTCPSummary(d.overlay.TCP)
		case layers.LayerTypeUDP:
			decoded.L4, sourcePort, destinationPort = decodeUDP(&d.overlay.UDP)
		case layers.LayerTypeSCTP:
			decoded.L4, sourcePort, destinationPort = decodeSCTP(&d.overlay.SCTP)
		case layers.LayerTypeICMPv4:
			decoded.L4 = decodeICMPv4(&d.overlay.ICMPv4)
			decoded.Summary = "ICMPv4 " + d.overlay.ICMPv4.TypeCode.String()
		case layers.LayerTypeICMPv6:
			decoded.L4 = decodeICMPv6(&d.overlay.ICMPv6)
			decoded.Summary = "ICMPv6 " + d.overlay.ICMPv6.TypeCode.String()
		case layers.LayerTypeVRRP:
			decoded.L4 = decodeVRRP(&d.overlay.VRRPv2)
			decoded.Summary = "VRRP " + d.overlay.VRRPv2.Type.String()
		case layers.LayerTypeIGMP:
			decoded.L4 = decodeIGMP(&d.overlay.IGMPv1or2)
			decoded.Summary = "IGMP " + d.overlay.IGMPv1or2.Type.String()
		}
	}

	return
}

func decodeVerdict(dn *monitor.DropNotify, tn *monitor.TraceNotify, pvn *monitor.PolicyVerdictNotify) pb.Verdict {
	switch {
	case dn != nil:
		return pb.Verdict_DROPPED
	case tn != nil:
		return pb.Verdict_FORWARDED
	case pvn != nil:
		if pvn.Verdict < 0 {
			return pb.Verdict_DROPPED
		}
		if pvn.Verdict > 0 {
			return pb.Verdict_REDIRECTED
		}
		if pvn.IsTrafficAudited() {
			return pb.Verdict_AUDIT
		}
		return pb.Verdict_FORWARDED
	}
	return pb.Verdict_VERDICT_UNKNOWN
}

func decodeDropReason(dn *monitor.DropNotify, pvn *monitor.PolicyVerdictNotify) uint32 {
	switch {
	case dn != nil:
		return uint32(dn.SubType)
	case pvn != nil && pvn.Verdict < 0:
		// if the flow was dropped, verdict equals the negative of the drop reason
		return uint32(-pvn.Verdict)
	}
	return 0
}

func decodeExtError(dn *monitor.DropNotify) int32 {
	if dn != nil {
		return int32(dn.ExtError)
	}
	return 0
}

func decodeExtDropReasonDesc(dn *monitor.DropNotify) string {
	if dn == nil {
		return ""
	}
	if dn.SubType == 0 && dn.ExtError == 0 {
		return ""
	}
	return monitorAPI.DropReasonExt(dn.SubType, dn.ExtError)
}

func decodeFileInfo(dn *monitor.DropNotify) *pb.FileInfo {
	switch {
	case dn != nil:
		return &pb.FileInfo{
			Name: monitorAPI.BPFFileName(dn.File),
			Line: uint32(dn.Line),
		}
	}
	return nil
}

func decodePolicyMatchType(pvn *monitor.PolicyVerdictNotify) uint32 {
	if pvn != nil {
		return uint32((pvn.Flags & monitor.PolicyVerdictNotifyFlagMatchType) >>
			monitor.PolicyVerdictNotifyFlagMatchTypeBitOffset)
	}
	return 0
}

func decodeEthernet(ethernet *layers.Ethernet) *pb.Ethernet {
	return &pb.Ethernet{
		Source:      formatMAC(ethernet.SrcMAC),
		Destination: formatMAC(ethernet.DstMAC),
	}
}

func decodeIPv4(ipv4 *layers.IPv4) (ip *pb.IP, src, dst netip.Addr) {
	// Ignore invalid IPs - getters will handle invalid values.
	// IPs can be empty for Ethernet-only packets.
	var srcStr, dstStr string
	if len(ipv4.SrcIP) == 4 {
		src = netip.AddrFrom4([4]byte(ipv4.SrcIP))
		srcStr = src.String()
	} else {
		src, _ = netipx.FromStdIP(ipv4.SrcIP)
		srcStr = ipv4.SrcIP.String()
	}
	if len(ipv4.DstIP) == 4 {
		dst = netip.AddrFrom4([4]byte(ipv4.DstIP))
		dstStr = dst.String()
	} else {
		dst, _ = netipx.FromStdIP(ipv4.DstIP)
		dstStr = ipv4.DstIP.String()
	}
	return &pb.IP{
		Source:      srcStr,
		Destination: dstStr,
		IpVersion:   pb.IPVersion_IPv4,
	}, src, dst
}

func decodeIPv6(ipv6 *layers.IPv6) (ip *pb.IP, src, dst netip.Addr) {
	// Ignore invalid IPs - getters will handle invalid values.
	// IPs can be empty for Ethernet-only packets.
	var srcStr, dstStr string
	if len(ipv6.SrcIP) == 16 {
		src = netip.AddrFrom16([16]byte(ipv6.SrcIP))
		srcStr = src.String()
	} else {
		src, _ = netipx.FromStdIP(ipv6.SrcIP)
		srcStr = ipv6.SrcIP.String()
	}
	if len(ipv6.DstIP) == 16 {
		dst = netip.AddrFrom16([16]byte(ipv6.DstIP))
		dstStr = dst.String()
	} else {
		dst, _ = netipx.FromStdIP(ipv6.DstIP)
		dstStr = ipv6.DstIP.String()
	}
	return &pb.IP{
		Source:      srcStr,
		Destination: dstStr,
		IpVersion:   pb.IPVersion_IPv6,
	}, src, dst
}

func decodeTCP(tcp *layers.TCP) (l4 *pb.Layer4, src, dst uint16) {
	return &pb.Layer4{
		Protocol: &pb.Layer4_TCP{
			TCP: &pb.TCP{
				SourcePort:      uint32(tcp.SrcPort),
				DestinationPort: uint32(tcp.DstPort),
				Flags:           pbTCPFlagsTable[tcpFlagsMask(*tcp)],
			},
		},
	}, uint16(tcp.SrcPort), uint16(tcp.DstPort)
}

func decodeSCTP(sctp *layers.SCTP) (l4 *pb.Layer4, src, dst uint16) {
	return &pb.Layer4{
		Protocol: &pb.Layer4_SCTP{
			SCTP: &pb.SCTP{
				SourcePort:      uint32(sctp.SrcPort),
				DestinationPort: uint32(sctp.DstPort),
				ChunkType:       decodeSCTPChunkType(sctp.Payload),
			},
		},
	}, uint16(sctp.SrcPort), uint16(sctp.DstPort)
}

func decodeSCTPChunkType(payload []byte) pb.SCTPChunkType {

	var chunktype pb.SCTPChunkType

	if len(payload) != 0 {
		switch layers.SCTPChunkType(payload[0]) {
		case layers.SCTPChunkTypeInit:
			chunktype = pb.SCTPChunkType_INIT
		case layers.SCTPChunkTypeInitAck:
			chunktype = pb.SCTPChunkType_INIT_ACK
		case layers.SCTPChunkTypeShutdown:
			chunktype = pb.SCTPChunkType_SHUTDOWN
		case layers.SCTPChunkTypeShutdownAck:
			chunktype = pb.SCTPChunkType_SHUTDOWN_ACK
		case layers.SCTPChunkTypeShutdownComplete:
			chunktype = pb.SCTPChunkType_SHUTDOWN_COMPLETE
		case layers.SCTPChunkTypeAbort:
			chunktype = pb.SCTPChunkType_ABORT
		default:
			chunktype = pb.SCTPChunkType_UNSUPPORTED
		}
	}
	return chunktype
}

func decodeUDP(udp *layers.UDP) (l4 *pb.Layer4, src, dst uint16) {
	return &pb.Layer4{
		Protocol: &pb.Layer4_UDP{
			UDP: &pb.UDP{
				SourcePort:      uint32(udp.SrcPort),
				DestinationPort: uint32(udp.DstPort),
			},
		},
	}, uint16(udp.SrcPort), uint16(udp.DstPort)
}

func decodeICMPv4(icmp *layers.ICMPv4) *pb.Layer4 {
	return &pb.Layer4{
		Protocol: &pb.Layer4_ICMPv4{ICMPv4: &pb.ICMPv4{
			Type: uint32(icmp.TypeCode.Type()),
			Code: uint32(icmp.TypeCode.Code()),
		}},
	}
}

func decodeICMPv6(icmp *layers.ICMPv6) *pb.Layer4 {
	return &pb.Layer4{
		Protocol: &pb.Layer4_ICMPv6{ICMPv6: &pb.ICMPv6{
			Type: uint32(icmp.TypeCode.Type()),
			Code: uint32(icmp.TypeCode.Code()),
		}},
	}
}

func decodeVRRP(vrrp *layers.VRRPv2) *pb.Layer4 {
	return &pb.Layer4{
		Protocol: &pb.Layer4_VRRP{VRRP: &pb.VRRP{
			Type:     uint32(vrrp.Type),
			Vrid:     uint32(vrrp.VirtualRtrID),
			Priority: uint32(vrrp.Priority),
		}},
	}
}

func decodeIGMP(igmp *layers.IGMPv1or2) *pb.Layer4 {
	return &pb.Layer4{
		Protocol: &pb.Layer4_IGMP{IGMP: &pb.IGMP{
			Type:         uint32(igmp.Type),
			GroupAddress: igmp.GroupAddress.String(),
		}},
	}
}

func decodeIsReply(tn *monitor.TraceNotify, pvn *monitor.PolicyVerdictNotify) *wrapperspb.BoolValue {
	switch {
	case tn != nil && tn.TraceReasonIsKnown():
		if tn.TraceReasonIsEncap() || tn.TraceReasonIsDecap() {
			return nil
		}
		// Reason was specified by the datapath, just reuse it.
		return boolValue(tn.TraceReasonIsReply())
	case pvn != nil && pvn.Verdict >= 0:
		// Forwarded PolicyVerdictEvents are emitted for the first packet of
		// connection, therefore we statically assume that they are not reply
		// packets
		return boolValueFalse
	default:
		// For other events, such as drops, we simply do not know if they were
		// replies or not.
		return nil
	}
}

func decodeCiliumEventType(eventType, eventSubType uint8) *pb.CiliumEventType {
	if eventType == monitorAPI.MessageTypeTrace && int(eventSubType) < len(traceCiliumEventTypes) {
		return traceCiliumEventTypes[eventSubType]
	}
	return &pb.CiliumEventType{
		Type:    int32(eventType),
		SubType: int32(eventSubType),
	}
}

func decodeTraceReason(tn *monitor.TraceNotify) pb.TraceReason {
	if tn == nil {
		return pb.TraceReason_TRACE_REASON_UNKNOWN
	}
	// The Hubble protobuf enum values aren't 1:1 mapped with Cilium's datapath
	// because we want pb.TraceReason_TRACE_REASON_UNKNOWN = 0 while in
	// datapath monitor.TraceReasonUnknown = 5. The mapping works as follow:
	switch {
	// monitor.TraceReasonUnknown is mapped to pb.TraceReason_TRACE_REASON_UNKNOWN
	case tn.TraceReason() == monitor.TraceReasonUnknown:
		return pb.TraceReason_TRACE_REASON_UNKNOWN
	// values before monitor.TraceReasonUnknown are "offset by one", e.g.
	// TraceReasonCtEstablished = 1 → TraceReason_ESTABLISHED = 2 to make room
	// for the zero value.
	case tn.TraceReason() < monitor.TraceReasonUnknown:
		return pb.TraceReason(tn.TraceReason()) + 1
	// all values greater than monitor.TraceReasonUnknown are mapped 1:1 with
	// the datapath values.
	default:
		return pb.TraceReason(tn.TraceReason())
	}
}

func decodeIpTraceId(dn *monitor.DropNotify, tn *monitor.TraceNotify) *pb.IPTraceID {
	var id uint64
	switch {
	case dn != nil:
		id = uint64(dn.IPTraceID)
	case tn != nil:
		id = uint64(tn.IPTraceID)
	}
	if id == 0 {
		return nil
	}
	return &pb.IPTraceID{
		TraceId:      id,
		IpOptionType: uint32(option.Config.IPTracingOptionType),
	}
}

func decodeSecurityIdentities(dn *monitor.DropNotify, tn *monitor.TraceNotify, pvn *monitor.PolicyVerdictNotify) (
	sourceSecurityIdentiy, destinationSecurityIdentity uint32,
) {
	switch {
	case dn != nil:
		sourceSecurityIdentiy = uint32(dn.SrcLabel)
		destinationSecurityIdentity = uint32(dn.DstLabel)
	case tn != nil:
		sourceSecurityIdentiy = uint32(tn.SrcLabel)
		destinationSecurityIdentity = uint32(tn.DstLabel)
	case pvn != nil:
		if pvn.IsTrafficIngress() {
			sourceSecurityIdentiy = uint32(pvn.RemoteLabel)
		} else {
			destinationSecurityIdentity = uint32(pvn.RemoteLabel)
		}
	}

	return
}

func decodeTrafficDirection(srcEP uint32, dn *monitor.DropNotify, tn *monitor.TraceNotify, pvn *monitor.PolicyVerdictNotify) pb.TrafficDirection {
	if dn != nil && dn.Source != 0 {
		// If the local endpoint at which the drop occurred is the same as the
		// source of the dropped packet, we assume it was an egress flow. This
		// implies that we also assume that dropped packets are not dropped
		// reply packets of an ongoing connection.
		if dn.Source == uint16(srcEP) {
			return pb.TrafficDirection_EGRESS
		}
		return pb.TrafficDirection_INGRESS
	}
	if tn != nil && tn.Source != 0 {
		// For trace events, we assume that packets may be reply packets of an
		// ongoing connection. Therefore, we want to access the connection
		// tracking result from the `Reason` field to invert the direction for
		// reply packets. The datapath currently populates the `Reason` field
		// with CT information for some observation points.
		if tn.TraceReasonIsKnown() {
			// true if the traffic source is the local endpoint, i.e. egress
			isSourceEP := tn.Source == uint16(srcEP)
			// when OrigIP is set, then the packet was SNATed
			isSNATed := !tn.OriginalIP().IsUnspecified()
			// true if the packet is a reply, i.e. reverse direction
			isReply := tn.TraceReasonIsReply()

			switch {
			// isSourceEP != isReply ==
			//  (isSourceEP && !isReply) || (!isSourceEP && isReply)
			case isSourceEP != isReply:
				return pb.TrafficDirection_EGRESS
			case isSNATed:
				return pb.TrafficDirection_EGRESS
			}
			return pb.TrafficDirection_INGRESS
		}
	}
	if pvn != nil {
		if pvn.IsTrafficIngress() {
			return pb.TrafficDirection_INGRESS
		}
		return pb.TrafficDirection_EGRESS
	}
	return pb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN
}

func getTCPFlags(tcp layers.TCP) string {
	return tcpFlagsStrings[tcpFlagsMask(tcp)]
}

func getTCPSummary(tcp layers.TCP) string {
	return tcpSummaryStrings[tcpFlagsMask(tcp)]
}

func decodeDebugCapturePoint(dbg *monitor.DebugCapture) pb.DebugCapturePoint {
	if dbg == nil {
		return pb.DebugCapturePoint_DBG_CAPTURE_POINT_UNKNOWN
	}
	return pb.DebugCapturePoint(dbg.SubType)
}

func (p *Parser) decodeNetworkInterface(tn *monitor.TraceNotify, dbg *monitor.DebugCapture) *pb.NetworkInterface {
	ifIndex := uint32(0)
	if tn != nil {
		ifIndex = tn.Ifindex
	} else if dbg != nil {
		switch dbg.SubType {
		case monitor.DbgCaptureDelivery,
			monitor.DbgCaptureFromLb,
			monitor.DbgCaptureAfterV46,
			monitor.DbgCaptureAfterV64,
			monitor.DbgCaptureSnatPre,
			monitor.DbgCaptureSnatPost:
			ifIndex = dbg.Arg1
		}
	}

	if ifIndex == 0 {
		return nil
	}

	var name string
	if p.linkGetter != nil {
		// if the interface is not found, `name` will be an empty string and thus
		// omitted in the protobuf message
		name, _ = p.linkGetter.GetIfNameCached(int(ifIndex))
	}
	return &pb.NetworkInterface{
		Index: ifIndex,
		Name:  name,
	}
}

func decodeProxyPort(dbg *monitor.DebugCapture, tn *monitor.TraceNotify) uint32 {
	if tn != nil && tn.ObsPoint == monitorAPI.TraceToProxy {
		return uint32(tn.DstID)
	} else if dbg != nil {
		switch dbg.SubType {
		case monitor.DbgCaptureProxyPre,
			monitor.DbgCaptureProxyPost:
			return byteorder.NetworkToHost32(dbg.Arg1)
		}
	}

	return 0
}
