package main

import (
	"log"
	"github.com/opbro/recap/pcapsummary"
)

func main() {
	log.Println("Main Method")
	var filename string = "pcaps/second_one.pcap"
	summary := pcapsummary.PcapSummary()
	summary.ProcessFile(filename)
	log.Println("Finished.")
}
