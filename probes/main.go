// Netpulse Data-Plane Probe
//
// Captures packets on a given interface, drops HL7 (port 2575), DICOM (port 104),
// and DICOM-TLS (port 2762) via BPF to avoid active scanning of medical/IoT devices,
// then publishes JSON telemetry to a RabbitMQ exchange.
//
// Usage:
//
//	RABBITMQ_URL=amqp://... PROBE_IFACE=eth0 ./probe
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	amqp "github.com/rabbitmq/amqp091-go"
)

// PacketEvent is the JSON payload pushed to RabbitMQ for each captured packet.
type PacketEvent struct {
	Timestamp   string `json:"ts"`
	SrcMAC      string `json:"src_mac,omitempty"`
	DstMAC      string `json:"dst_mac,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	Protocol    string `json:"proto,omitempty"`
	SrcPort     uint16 `json:"src_port,omitempty"`
	DstPort     uint16 `json:"dst_port,omitempty"`
	PayloadLen  int    `json:"payload_len"`
}

const (
	exchangeName = "netpulse.telemetry"
	routingKey   = "probe.packet"
	snapLen      = 1600
	promiscuous  = true
	timeout      = pcap.BlockForever

	// BPF filter: capture everything EXCEPT HL7 (2575), DICOM (104), DICOM-TLS (2762).
	// Dropping these prevents accidental active probing of medical-grade devices.
	bpfFilter = "not (tcp port 2575 or tcp port 104 or tcp port 2762)"
)

func mustGetenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func connectAMQP(url string) (*amqp.Connection, *amqp.Channel, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, nil, fmt.Errorf("amqp dial: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("amqp channel: %w", err)
	}
	if err = ch.ExchangeDeclare(exchangeName, "topic", true, false, false, false, nil); err != nil {
		ch.Close()
		conn.Close()
		return nil, nil, fmt.Errorf("exchange declare: %w", err)
	}
	return conn, ch, nil
}

func publish(ch *amqp.Channel, evt PacketEvent) error {
	body, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	return ch.Publish(exchangeName, routingKey, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Transient,
		Timestamp:    time.Now(),
		Body:         body,
	})
}

func main() {
	rabbitURL := mustGetenv("RABBITMQ_URL", "amqp://netpulse:netpulse@localhost:5672/netpulse")
	iface := mustGetenv("PROBE_IFACE", "eth0")

	// Open the network interface for packet capture.
	handle, err := pcap.OpenLive(iface, snapLen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("pcap open %s: %v", iface, err)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatalf("bpf filter: %v", err)
	}

	log.Printf("probe: capturing on %s (filter: %s)", iface, bpfFilter)

	// Connect to RabbitMQ with simple retry.
	var conn *amqp.Connection
	var ch *amqp.Channel
	for attempt := 1; attempt <= 10; attempt++ {
		conn, ch, err = connectAMQP(rabbitURL)
		if err == nil {
			break
		}
		log.Printf("probe: amqp connect attempt %d/10: %v", attempt, err)
		// Cap backoff at 30 seconds to avoid excessive wait times.
		delay := time.Duration(attempt) * 2 * time.Second
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		time.Sleep(delay)
	}
	if err != nil {
		log.Fatalf("probe: could not connect to RabbitMQ: %v", err)
	}
	defer conn.Close()
	defer ch.Close()

	// Graceful shutdown on SIGTERM/SIGINT.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	for {
		select {
		case <-stop:
			log.Println("probe: shutting down")
			return
		case pkt, ok := <-src.Packets():
			if !ok {
				return
			}
			evt := buildEvent(pkt)
			if pubErr := publish(ch, evt); pubErr != nil {
				log.Printf("probe: publish error: %v", pubErr)
			}
		}
	}
}

func buildEvent(pkt gopacket.Packet) PacketEvent {
	evt := PacketEvent{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		PayloadLen: len(pkt.Data()),
	}

	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		e := eth.(*layers.Ethernet)
		evt.SrcMAC = e.SrcMAC.String()
		evt.DstMAC = e.DstMAC.String()
	}

	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		i := ip4.(*layers.IPv4)
		evt.SrcIP = i.SrcIP.String()
		evt.DstIP = i.DstIP.String()
		evt.Protocol = i.Protocol.String()
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		i := ip6.(*layers.IPv6)
		evt.SrcIP = i.SrcIP.String()
		evt.DstIP = i.DstIP.String()
		evt.Protocol = i.NextHeader.String()
	}

	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		evt.SrcPort = uint16(t.SrcPort)
		evt.DstPort = uint16(t.DstPort)
	} else if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		evt.SrcPort = uint16(u.SrcPort)
		evt.DstPort = uint16(u.DstPort)
	}

	return evt
}
