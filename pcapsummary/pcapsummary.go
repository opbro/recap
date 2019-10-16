package pcapsummary

import (
	"log"
        "math"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

//PcapSummary Holds summary information from parsing a .pcaps
type PcapSummary struct {
	l2flows map[string]string
	l3flows map[string]string
	macToip map[string]map[string]bool
}

//NewPcapSummary initializes a PcapSummary with empty maps
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

func (summary PcapSummary) sumMacToIP(linkLayer gopacket.LinkLayer, networkLayer gopacket.NetworkLayer) {

	if networkLayer != nil && linkLayer != nil {
		ip := networkLayer.NetworkFlow().Dst().String()
		mac := linkLayer.LinkFlow().Dst().String()
		if summary.macToip[mac] == nil {
			summary.macToip[mac] = make(map[string]bool)
		}
		summary.macToip[mac][ip] = true
	}

}

//ProcessFile will summarize a pcap and add/update its results to the current PcapSummary
func (summary PcapSummary) ProcessFile(filename string) {
	log.Println("Trying to open: ", filename)
	if handle, err := pcap.OpenOffline(filename); err != nil {
		log.Fatal(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		count := 0
		start := time.Now()
		for packet := range packetSource.Packets() {
			incrementalStart := time.Now()
			linkLayer := packet.LinkLayer()
			networkLayer := packet.NetworkLayer()
			summary.sumLinkLayer(linkLayer)
			summary.sumNetworkLayer(networkLayer)
			summary.sumMacToIP(linkLayer, networkLayer)
			count++
			if math.Mod(float64(count), 200000) == 0 {
				incrementalElapsed := time.Since(incrementalStart)
				log.Println("Proccessed ", count, " packets in ", incrementalElapsed, " seconds")
			}
		}
		elapsed := time.Since(start)
		log.Println("Total Packets processed: ", count, " in ", elapsed, " seconds")
	}
}
