package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	netfilter "github.com/AkihiroSuda/go-netfilter-queue"

	_ "github.com/google/gopacket/layers"
)

// import gopacket layers!!
// https://pkg.go.dev/github.com/google/gopacket#hdr-A_Final_Note

// https://pkg.go.dev/github.com/google/gopacket#Packet

// https://pkg.go.dev/github.com/google/gopacket/layers

// // https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket

type AutoMulticastTunneling struct {
    Type    byte
}

const debugLevel = 11

func main() {

    nfq, err := netfilter.NewNFQueue(1, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
    if err != nil {
            fmt.Println(err)
            os.Exit(1)
    }
    defer nfq.Close()
    packets := nfq.GetPackets()

    // "golang.org/x/time/rate"
    // https://pkg.go.dev/golang.org/x/time/rate
    // limiter := rate.NewLimiter(rate.Limit(100), 1)
    //limiter := rate.NewLimiter(rate.Every(30*time.Second), 3)

    // "github.com/Narasimha1997/ratelimiter"
    // // https://github.com/Narasimha1997/ratelimiter
	// limiter := ratelimiter.NewDefaultLimiter(
	// 	2,
    //     30*time.Second,
	// )

    t := time.NewTicker(30 * time.Second)

    var amt AutoMulticastTunneling
    allowedPkts := 2

    for {
        p := <-packets

        select {
        case <-t.C:
            if debugLevel > 10 {
                log.Println("allowedPkts+=2:",allowedPkts,"<---------")
            }
            allowedPkts+=2
        default:
        }

        if debugLevel > 100 {
            log.Println(p.Packet)
        }
        if debugLevel > 100 {
            log.Println("old:",hex.EncodeToString(p.Packet.Data()))
        }

        err := binary.Read(bytes.NewReader(p.Packet.ApplicationLayer().Payload()), binary.LittleEndian, &amt)
        if err != nil {
            panic(err)
        }

        if debugLevel > 100 {
            log.Println("app payload:",hex.EncodeToString(p.Packet.ApplicationLayer().Payload()))
        }

        if amt.Type != 0x03 {
            if debugLevel > 100 {
                log.Println("Not equal to 0x03, so NOT touching this packet")
            }
            p.SetVerdict(netfilter.NF_ACCEPT)
            continue
        }

        if debugLevel > 100 {
            log.Println("Type 0x03, so going to apply rate limiting")
        }

        // allow, err := limiter.ShouldAllow(1)
        // if err != nil{
        //     panic(err)
        // }

        // if limiter.Allow() {
        //     if debugLevel > 10 {
        //         fmt.Println("limiter.Allow()")
        //     }
        //     p.SetVerdict(netfilter.NF_ACCEPT)
        // } else{
        //     if debugLevel > 10 {
        //         fmt.Println("!limiter.Allow() - DROP")
        //     }
        //     p.SetVerdict(netfilter.NF_DROP)
        // }
        if allowedPkts > 0 {
            if debugLevel > 10 {
                log.Println("allowedPkts >0:",allowedPkts)
            }
            p.SetVerdict(netfilter.NF_ACCEPT)
            allowedPkts--
        } else {
            if debugLevel > 10 {
                log.Println("allowedPkts !> 0:",allowedPkts)
            }
            p.SetVerdict(netfilter.NF_DROP)
        }
    }
}