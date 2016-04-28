/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.prof.salesfilho.sna;

import br.prof.salesfilho.sna.analyzer.PacketFlowAnalyzer;
import br.prof.salesfilho.sna.capture.CapturePacket;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.PostConstruct;
import lombok.Getter;
import org.jnetpcap.PcapIf;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.SimpleCommandLinePropertySource;
import org.springframework.stereotype.Component;

/**
 *
 * @author salesfilho
 */
@Component
public class Main {

    @Autowired
    private ApplicationArguments applicationArguments;

    @Autowired
    private CapturePacket capturePacket;

    @Autowired
    private PacketFlowAnalyzer packetFlowAnalyzer;

    @Getter
    private PropertySource propertySource;

    private boolean start = true;

    @PostConstruct
    public void init() throws FileNotFoundException, IOException {
        propertySource = new SimpleCommandLinePropertySource(applicationArguments.getSourceArgs());

        if (this.propertySource.containsProperty("capture")) {
            this.startCapture();
        } else if (this.propertySource.containsProperty("analyze")) {
            this.startAnalyzer();
        } else {
            this.usage();
        }
    }

    public void startCapture() {

        if (this.propertySource.containsProperty("interface")) {
            for (PcapIf iface : capturePacket.getAllDevices()) {
                if (iface.getName().equals(this.propertySource.getProperty("interface"))) {
                    capturePacket.setDevice(iface);
                    break;
                }
            }
            if (capturePacket.getDevice() == null) {
                System.out.println("Interface not present!");
                for (PcapIf iface : capturePacket.getAllDevices()) {
                    System.out.println("INTERFACE:  " + iface.getName() + "( " + iface.getDescription() + " )");
                }
                this.start = false;
            }

        } else {
            this.start = false;
        }

        if (this.propertySource.containsProperty("file")) {
            capturePacket.setOutputFile(this.propertySource.getProperty("file").toString());

        } else {
            capturePacket.setOutputFile("capture-" + System.currentTimeMillis() + ".pcap");
            System.out.println("Capture file: " + capturePacket.getOutputFile());
        }

        if (this.start) {
            //Initialyze capture
            capturePacket.startCapture();
        } else {
            usage();
        }

    }

    public void startAnalyzer() throws FileNotFoundException, IOException {
        if (this.propertySource.containsProperty("file")) {
            packetFlowAnalyzer.setInputFile(this.propertySource.getProperty("file").toString());
        } else {
            System.out.println("file parameter not set");
            this.start = false;
        }
        if (this.propertySource.containsProperty("outputdir")) {
            packetFlowAnalyzer.setFileOutputPath(this.propertySource.getProperty("outputdir").toString());
        }
        if (this.propertySource.containsProperty("mimetype")) {
            List<String> types = new ArrayList();
            String[] mimes = this.propertySource.getProperty("mimetype").toString().split(",");
            types.addAll(Arrays.asList(mimes));
            packetFlowAnalyzer.setFileTypeToSaveList(types);
        } else {
            System.out.println("mimetype parameter not set");
            this.start = false;
        }
        if (this.start) {
            packetFlowAnalyzer.openOfflineCapture();
            packetFlowAnalyzer.analyze();
            packetFlowAnalyzer.closeOfflineCapture();
        } else {
            usage();
        }

    }

    private void usage() {
        System.out.println("------------------------------------------------------------------------------------");
        System.out.println("");
        System.out.println("Usage: java -jar sna<version>.jar options");
        System.out.println("Main Options: --capture || --analyze");
        System.out.println("");
        System.out.println("Ex.: Capture: java -jar sna.jar --capture --interface=eth0 --file=/tmp/capture.pcap");
        System.out.println("Ex.: Analyze: java -jar sna.jar --analyze  --file=/tmp/capture.pcap --outputdir=/tmp --mimetype=image/jpeg");
        System.out.println("");

        System.out.println("------------------------------------------------------------------------------------");

    }

}
