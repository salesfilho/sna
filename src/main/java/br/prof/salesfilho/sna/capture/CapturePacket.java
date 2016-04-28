/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.prof.salesfilho.sna.capture;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.springframework.stereotype.Component;

/**
 *
 * @author salesfilho
 */
@Component
public class CapturePacket {

    @Setter
    private List<PcapIf> allDevices = new ArrayList(); // Will be filled with NICs  

    @Getter
    @Setter
    private PcapIf device;

    @Getter
    private final StringBuilder errorBuffer = new StringBuilder();     // For any error msgs  

    @Getter
    @Setter
    private String outputFile;

    @Getter
    @Setter
    private int snaplen;

    @Getter
    @Setter
    private int flags;

    @Getter
    @Setter
    private int timeout;

    public CapturePacket() {
        /*
         Setup default variables value
         */
        this.setSnaplen(64 * 1024);             // CapturePacket all packets, no trucation  
        this.setFlags(Pcap.MODE_PROMISCUOUS);  // capture all packets  
        this.setTimeout(10 * 1000);           // 10 seconds in millis  

    }

    public void startCapture() {
        Pcap cap = this.getPcap(this.getDevice().getName(), this.getSnaplen(), this.getFlags(), this.getTimeout());
        this.dumper(cap);
    }

    public List<PcapIf> getAllDevices() {
        int result = Pcap.findAllDevs(allDevices, errorBuffer);
        if (!(result == Pcap.OK) || allDevices.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s\n", errorBuffer.toString());
        }
        return allDevices;
    }

    public Pcap getPcap(String deviceName, int snaplen, int flags, int timeout) {
        Pcap pcap = Pcap.openLive(deviceName, snaplen, flags, timeout, errorBuffer);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: %s\n", errorBuffer.toString());
            return null;
        }
        return pcap;
    }

    public void dumper(Pcap pcap) {
        final PcapDumper dumper = pcap.dumpOpen(getOutputFile()); // output file 
        final Ip4 ip = new Ip4();
        final Tcp tcp = new Tcp();

        PcapPacketHandler jpacketHandler = new PcapPacketHandler() {
            @Override
            public void nextPacket(PcapPacket packet, Object user) {
                dumper.dump(packet);

                if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                    System.out.println("************** BEGIN PACKET *************************");
                    System.out.println("Src IP:" + FormatUtils.ip(ip.source()));
                    System.out.println("Dst IP: " + FormatUtils.ip(ip.destination()));
                    System.out.println("Src port: " + tcp.source());
                    System.out.println("Dst: port" + tcp.destination());
                    System.out.println("************** END PAKET*************************");
                }
            }
        };

        System.out.println("**** Starting capture... ****");

        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "SNA Capture");

        File file = new File(getOutputFile());
        System.out.printf("%s file has %d bytes in it!\n", getOutputFile(), file.length());

        dumper.close(); // Won't be able to delete without explicit close  
        pcap.close();
    }
}
