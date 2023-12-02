package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

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
    Reserved [3]byte
    Nonce [4]byte
    IP  [4]byte
}

// var CustomLayerType = gopacket.RegisterLayerType(
//     2001,
//     gopacket.LayerTypeMetadata{
//         "CustomLayerType",
//         gopacket.DecodeFunc(decodeCustomLayer),
//     },
// )

// func (l AMTLayer) LayerType() gopacket.LayerType {
//     return CustomLayerType
// }

// func (l AMTLayer) LayerContents() []byte {
//     return []byte{l.SomeByte, l.AnotherByte}
// }

// func (l AMTLayer) LayerPayload() []byte {
//     return l.restOfData
// }

// func decodeCustomLayer(data []byte, p gopacket.PacketBuilder) error {
//     p.AddLayer(
//         &AMTLayer{
//             data[0],
//             data[1:3],
//             data[4:7],
//             data[8:11],
//         },
//     )
//     return p.NextDecoder(gopacket.LayerTypePayload)
// }

const debugLevel = 11

func main() {

    nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
    if err != nil {
            fmt.Println(err)
            os.Exit(1)
    }
    defer nfq.Close()
    packets := nfq.GetPackets()

    var amt AutoMulticastTunneling

    for {
        p := <-packets
        if debugLevel > 10 {
            fmt.Println(p.Packet)
        }
        if debugLevel > 10 {
            fmt.Println("old:",hex.EncodeToString(p.Packet.Data()))
        }

        err := binary.Read(bytes.NewReader(p.Packet.ApplicationLayer().Payload()), binary.LittleEndian, &amt)
        if err != nil {
            panic(err)
        }

        if amt.Type != 0x02 {
            p.SetVerdict(netfilter.NF_ACCEPT)
        }

        if debugLevel > 10 {
            fmt.Println("yay!!!")
        }

        // Here we build a new packet by copying most of the fields, but not all
        // We want gopacket to recalculate the checksums at IP and UDP layers

        // https://pkg.go.dev/github.com/google/gopacket#hdr-Creating_Packet_Data

        // DOES NOT HAVE ETHER LAYER BY THE TIME IT GETS TO IPTABLES

        // https://pkg.go.dev/github.com/google/gopacket/layers#Ethernet
        newEthLayer := &layers.Ethernet{}
        ethLayer := p.Packet.Layer(layers.LayerTypeEthernet)
        if ethLayer != nil {
            ethFrame, _ := ethLayer.(*layers.Ethernet)
            fmt.Println("eth source address:", ethFrame.SrcMAC)
            fmt.Println("eth destination address:", ethFrame.DstMAC)
            newEthLayer.SrcMAC = ethFrame.SrcMAC
            newEthLayer.DstMAC = ethFrame.DstMAC
            newEthLayer.EthernetType = ethFrame.EthernetType
        }

        // https://pkg.go.dev/github.com/google/gopacket/layers#IPv4
        newIpLayer := &layers.IPv4{}
        ipLayer := p.Packet.Layer(layers.LayerTypeIPv4)
        if ipLayer != nil {
            ipPacket, _ := ipLayer.(*layers.IPv4)
            fmt.Println("IP source address:", ipPacket.SrcIP)
            fmt.Println("IP destination address:", ipPacket.DstIP)
            newIpLayer.Version = ipPacket.Version
            newIpLayer.Id = ipPacket.Id
            newIpLayer.TTL = ipPacket.TTL
            newIpLayer.SrcIP = ipPacket.SrcIP
            newIpLayer.DstIP = ipPacket.DstIP
            newIpLayer.Protocol = ipPacket.Protocol
        }

        // https://pkg.go.dev/github.com/google/gopacket/layers#UDP
        newUdpLayer := &layers.UDP{}
        udpLayer := p.Packet.Layer(layers.LayerTypeUDP)
        if ipLayer != nil {
            udpPacket, _ := udpLayer.(*layers.UDP)
            fmt.Println("source port:", udpPacket.SrcPort)
            fmt.Println("destination port:", udpPacket.DstPort)
            newUdpLayer.SrcPort = udpPacket.SrcPort
            newUdpLayer.DstPort = udpPacket.DstPort
        }

        b := p.Packet.ApplicationLayer().Payload()
        // 18.118.31.124
        //[]byte{0x12,0x76,0x1F,0x7C}
        b[len(b)-1] = 0x12
        b[len(b)-1] = 0x76
        b[len(b)-1] = 0x1F
        b[len(b)-1] = 0x7C

        var options      gopacket.SerializeOptions
        buffer := gopacket.NewSerializeBuffer()
        gopacket.SerializeLayers(
            buffer,
            options,
            newIpLayer,
            newUdpLayer,
            gopacket.Payload(b),
        )

        if debugLevel > 10 {
            //fmt.Println("old:",hex.EncodeToString(p.Packet.Data()))
            fmt.Println("new:",hex.EncodeToString(buffer.Bytes()))
        }

        p.SetVerdictWithPacket(netfilter.NF_ACCEPT, buffer.Bytes())
    }
}