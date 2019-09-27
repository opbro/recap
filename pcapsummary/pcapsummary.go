package pcapsummary

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PcapSummary struct {
	l2flows map[string]string
	l3flows map[string]string
	macToip map[string]map[string]bool
}

func NewPcapSummary() *PcapSummary {
	var tmp PcapSummary
	tmp.l2flows = make(map[string]string)
	tmp.l3flows = make(map[string]string)
	tmp.macToip = make(map[string]map[string]bool)

	return &tmp
}

func (summary PcapSummary) sumLinkLayer(linkLayer gopacket.LinkLayer) {
	if linkLayer != nil {
		src := linkLayer.LinkFlow().Src().String()
		dest := linkLayer.LinkFlow().Dst().String()
		if summary.l2flows[src] == "" {
			summary.l2flows[src] = dest
		}
	}
}

func (summary PcapSummary) sumNetworkLayer(networkLayer gopacket.NetworkLayer) {
	if networkLayer != nil {
		src := networkLayer.NetworkFlow().Src().String()
		dest := networkLayer.NetworkFlow().Dst().String()
		if summary.l3flows[src] == "" {
			summary.l3flows[src] = dest
		}
	}

}

func (summary PcapSummary) sumMacToIp(linkLayer gopacket.LinkLayer, networkLayer gopacket.NetworkLayer) {

	if networkLayer != nil && linkLayer != nil {
		ip := networkLayer.NetworkFlow().Dst().String()
		mac := linkLayer.LinkFlow().Dst().String()
		if summary.macToip[mac] == nil {
			summary.macToip[mac] = make(map[string]bool)
		}
		summary.macToip[mac][ip] = true
	}

}

func (summary PcapSummary) ProcessFile(filename string) {
	log.Println("Trying to open: ", filename)
	if handle, err := pcap.OpenOffline(filename); err != nil {
		log.Fatal(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			linkLayer := packet.LinkLayer()
			networkLayer := packet.NetworkLayer()
			summary.sumLinkLayer(linkLayer)
			summary.sumNetworkLayer(networkLayer)
			summary.sumMacToIp(linkLayer, networkLayer)
		}
	}
}
