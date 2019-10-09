package main

import (
	"log"
	"flag"
	"github.com/opbro/recap/pcapsummary"
)

func main() {
	filename := flag.String("f", "pcaps/second_one.pcap", "pcap file to process")
	flag.Parse()
	log.Println("Main Method")
	summary := pcapsummary.NewPcapSummary()
	summary.ProcessFile(*filename)
	log.Println("Finished.")
}
