// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"strconv"
	"strings"

	"github.com/gopacket/gopacket/layers"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

func decodeDNS(flowType accesslog.FlowType, dns *accesslog.LogRecordDNS) *flowpb.Layer7_Dns {
	var qtypes []string
	if n := len(dns.QTypes); n > 0 {
		qtypes = make([]string, n)
		for i, qtype := range dns.QTypes {
			qtypes[i] = layers.DNSType(qtype).String()
		}
	}
	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return &flowpb.Layer7_Dns{
			Dns: &flowpb.DNS{
				Query:             dns.Query,
				ObservationSource: string(dns.ObservationSource),
				Qtypes:            qtypes,
			},
		}
	}
	var ips []string
	if n := len(dns.IPs); n > 0 {
		ips = make([]string, n)
		for i, ip := range dns.IPs {
			ips[i] = ip.String()
		}
	}
	var rtypes []string
	if n := len(dns.AnswerTypes); n > 0 {
		rtypes = make([]string, n)
		for i, rtype := range dns.AnswerTypes {
			rtypes[i] = layers.DNSType(rtype).String()
		}
	}
	return &flowpb.Layer7_Dns{
		Dns: &flowpb.DNS{
			Query:             dns.Query,
			Ips:               ips,
			Ttl:               dns.TTL,
			Cnames:            dns.CNAMEs,
			ObservationSource: string(dns.ObservationSource),
			Rcode:             uint32(dns.RCode),
			Qtypes:            qtypes,
			Rrtypes:           rtypes,
		},
	}
}

func dnsSummary(flowType accesslog.FlowType, dns *accesslog.LogRecordDNS) string {
	var qTypeStr string
	switch len(dns.QTypes) {
	case 0:
	case 1:
		qTypeStr = layers.DNSType(dns.QTypes[0]).String()
	default:
		types := make([]string, len(dns.QTypes))
		for i, t := range dns.QTypes {
			types[i] = layers.DNSType(t).String()
		}
		qTypeStr = strings.Join(types, ",")
	}

	switch flowType {
	case accesslog.TypeRequest:
		return "DNS Query " + dns.Query + " " + qTypeStr
	case accesslog.TypeResponse:
		rcode := layers.DNSResponseCode(dns.RCode)

		var answer string
		if rcode != layers.DNSResponseCodeNoErr {
			answer = "RCode: " + rcode.String()
		} else {
			parts := make([]string, 0, 2)

			if len(dns.IPs) > 0 {
				if len(dns.IPs) == 1 {
					parts = append(parts, strconv.Quote(dns.IPs[0].String()))
				} else {
					ips := make([]string, len(dns.IPs))
					for i, ip := range dns.IPs {
						ips[i] = ip.String()
					}
					parts = append(parts, strconv.Quote(strings.Join(ips, ",")))
				}
			}

			if len(dns.CNAMEs) > 0 {
				parts = append(parts, "CNAMEs: "+strconv.Quote(strings.Join(dns.CNAMEs, ",")))
			}

			answer = strings.Join(parts, " ")
		}

		sourceType := "Query"
		if dns.ObservationSource == accesslog.DNSSourceProxy {
			sourceType = "Proxy"
		}

		var buf [160]byte
		b := buf[:0]
		b = append(b, "DNS Answer "...)
		b = append(b, answer...)
		b = append(b, " TTL: "...)
		b = strconv.AppendUint(b, uint64(dns.TTL), 10)
		b = append(b, " ("...)
		b = append(b, sourceType...)
		b = append(b, ' ')
		b = append(b, dns.Query...)
		b = append(b, ' ')
		b = append(b, qTypeStr...)
		b = append(b, ')')
		return string(b)
	}

	return ""
}
