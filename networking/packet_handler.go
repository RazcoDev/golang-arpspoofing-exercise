package networking

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

type DnsQuery struct {
	SrcIP     net.IP
	DNSAnswer []byte
}

func GetDNSQueries(device string, timer time.Duration) ([]byte, error) {
	log.Println("Capturing dns packets from interface " + device)
	a, err := startSniffingPCAP(device, timer)

	return a, err

}

func startSniffingPCAP(device string, timer time.Duration) ([]byte, error) {
	endSignal := make(chan bool, 1)
	handle, err := pcap.OpenLive(device, 1024, false, -1)
	if err != nil {
		log.Println(err)
	}

	go func(endSignal chan<- bool) {
		time.Sleep(timer * time.Second)
		endSignal <- true
	}(endSignal)
	dnsQueriesSlice := make([]DnsQuery, 0)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			ipLayer4 := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer4 != nil {
				ip, _ := ipLayer4.(*layers.IPv4)
				dns, _ := dnsLayer.(*layers.DNS)
				if dns.Answers != nil {
					log.Printf("From %s, data: %s \n", ip.SrcIP, dns.Questions[0].Name)
					dnsQueriesSlice = append(dnsQueriesSlice, DnsQuery{SrcIP: ip.SrcIP, DNSAnswer: dns.Questions[0].Name})
				}
			}
		}

		if len(endSignal) != 0 {
			dnsQueriesJson, err := json.Marshal(dnsQueriesSlice)
			handle.Close()
			return dnsQueriesJson, err

		}
	}

	return nil, err
}
