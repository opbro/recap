package main

import (
	"log"

	"github.com/opbro/recap/pcapsummary"
)

func main() {
	log.Println("Main Method")
	var filename string = "pcaps/second_one.pcap"
	summary := pcapsummary.NewPcapSummary()
	summary.ProcessFile(filename)
	log.Println("Finished.")
}
