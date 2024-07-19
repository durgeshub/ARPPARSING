package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/muonsoft/validation/validate"
)

var table = make(map[string]string)

func main() {

	wait := &sync.WaitGroup{}
	ch1 := make(chan layers.ARP)
	ch2 := make(chan gopacket.Packet)
	// var inP string

	for {

		wait.Add(2)

		go sender(ch1, ch2, wait)

		go receiver(ch1, table, ch2, wait)

		wait.Wait()
	}
}

func sender(ch1 chan layers.ARP, ch2 chan gopacket.Packet, wait *sync.WaitGroup) {
	var input string
	fmt.Println("enter the ip address")
	fmt.Scan(&input)
	err := validate.IPv4(input)
	if err == nil {
		fmt.Println("you have entered valid IP address")

	} else {
		fmt.Println(err)
		os.Exit(2)

	}

	ip := net.ParseIP(input)

	srcMAC := net.HardwareAddr{0x00, 0x0c, 0x29, 0x2e, 0x3b, 0x4a}
	srcIP := net.IP{192, 168, 1, 100}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} //mac of broadcast so that request will reach to every device in the broadcast
	dstIp := ip

	arpreq := ARPRequest(srcMAC, srcIP, dstMAC, dstIp)
	// fmt.Println(arp)

	ch1 <- arpreq
	// fmt.Println(<-ch2)
	readARP(<-ch2)
	wait.Done()
}

func receiver(ch1 chan layers.ARP, table map[string]string, ch2 chan gopacket.Packet, wait *sync.WaitGroup) {
	table["10.10.200.1"] = "94-ff-3c-35-63-1a"
	table["10.10.200.102"] = "d8-8c-79-55-c1-1a"
	table["10.10.200.138"] = "94-ff-3c-35-63-f1"
	table["10.10.200.233"] = "b0-2a-43-87-cf-e5"
	table["224.0.0.250"] = "20-89-8a-35-63-50"
	table["224.0.0.251"] = "ff-ff-ff-ff-ff-ff"
	table["233.89.188.1"] = "01-00-5e-00-00-16"
	arpreq := <-ch1

	ipnet := readip(arpreq)
	ip := ipnet.String()
	elem := table[ip]

	if elem == "" {
		fmt.Println("Failure no MAC-matching")
		os.Exit(3)

	} else {
		fmt.Println("Success found MAC-matching sending ARP reply")
		replypacket := ARPREPLY(arpreq.DstProtAddress, arpreq)
		ch2 <- replypacket

	}

	wait.Done()

}
func ARPRequest(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) layers.ARP {

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arpreq := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arpreq)

	return arpreq
}
func ARPREPLY(ip net.IP, arpreq layers.ARP) gopacket.Packet {

	mapip := ip.String() //to make mapping in the table or we need to encode source hardwareaddress for that we need to extract it from the table
	strmac := table[mapip]
	srcMAC, _ := net.ParseMAC(strmac)
	srcIP := ip
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       arpreq.SourceHwAddress,
		EthernetType: layers.EthernetTypeARP,
	}

	arpreply := layers.ARP{
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   6,
		ProtAddressSize: 4,

		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      arpreq.SourceHwAddress,
		DstProtAddress:    arpreq.SourceProtAddress,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arpreply)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

}

func readip(arp layers.ARP) net.IP {
	return (arp.DstProtAddress)
}

func readARP(arpreplypacket gopacket.Packet) {

	arpLayer := arpreplypacket.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		fmt.Println("not an ARP packet")
	}
	arp := arpLayer.(*layers.ARP)
	if arp.Operation != layers.ARPReply {

		fmt.Println("Not a reply")
	}

	log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
}
