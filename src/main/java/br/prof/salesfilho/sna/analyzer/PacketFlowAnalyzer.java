/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.prof.salesfilho.sna.analyzer;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.apache.tika.Tika;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.springframework.stereotype.Component;

/**
 *
 * @author salesfilho
 */
@Component
public class PacketFlowAnalyzer {

    @Getter
    @Setter
    private Pcap pcap;

    @Getter
    @Setter
    private String inputFile;

    @Getter
    @Setter
    private String fileOutputPath = "/tmp/";

    @Getter
    @Setter
    private List<String> fileTypeToSaveList = new ArrayList<>();

    @Getter
    @Setter
    private FileOutputStream fileOutputStream;

    private ByteArrayOutputStream byteArrayOutputStream;

    public void analyze() throws FileNotFoundException, IOException {

        final Tcp tcp = new Tcp();
        final Ip4 ip = new Ip4();

        boolean started_file_save = false;
        byte[] payload;
        String fileType;
        String fileName = "";
        int countFile = 0;

        for (JPacket packet : getReverseFlow()) {
            if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                payload = tcp.getPayload();
                fileType = getFileMimeType(payload);
                System.out.println("Detecting file type:" + fileType);
                if (isTypesToSave(fileType)) {

                    if (started_file_save) {

                        saveAndCloseOutputFile();
                        System.out.println("Save file complete:" + fileName);

                        fileName = System.currentTimeMillis() + getFileExtension(fileType);
                        System.out.println("Starting saving new file..." + fileName);

                        newOutputFile(fileName);
                        addByteToArray(payload);
                        started_file_save = true;
                        countFile++;

                    } else {
                        fileName = System.currentTimeMillis() + getFileExtension(fileType);
                        System.out.println("Starting saving file..." + fileName);
                        newOutputFile(fileName);
                        addByteToArray(payload);
                        started_file_save = true;
                        countFile++;
                    }
                } else if (fileType.equalsIgnoreCase("application/octet-stream") && started_file_save) {
                    System.out.println("Continuing saving file...");
                    addByteToArray(payload);
                } else {
                    System.out.println("Packet filetype no match:" + fileType);
                }
            }
        }
        if (started_file_save) {
            saveAndCloseOutputFile();
        }
        System.out.println("File(s) extracted:" + countFile);
    }

    public JFlowMap getAllPacketFlow() {
        JFlowMap superFlowMap = new JFlowMap();
        this.pcap.loop(Pcap.LOOP_INFINITE, superFlowMap, null);
        return superFlowMap;
    }

    public List<JPacket> getReverseFlow() {
        List<JPacket> result = new ArrayList<>();
        for (Map.Entry<JFlowKey, JFlow> entrySet : getAllPacketFlow().entrySet()) {
            JFlowKey key = entrySet.getKey();
            JFlow flow = entrySet.getValue();

            if (flow.isReversable()) {
                result.addAll(flow.getReverse());
            }
        }
        return result;
    }

    public List<JPacket> getForwardFlow() {
        List<JPacket> result = new ArrayList<>();
        for (Map.Entry<JFlowKey, JFlow> entrySet : getAllPacketFlow().entrySet()) {
            JFlowKey key = entrySet.getKey();
            JFlow flow = entrySet.getValue();

            if (flow.isReversable()) {
                result.addAll(flow.getForward());
            }
        }
        return result;
    }

    public List<JPacket> getTcpPacketFrom(byte[] hostIp) {
        final Tcp tcp = new Tcp();
        final Ip4 ip = new Ip4();

        List<JPacket> result = new ArrayList<>();
        for (JPacket packet : getForwardFlow()) {
            if (packet.hasHeader(ip) && Arrays.equals(ip.source(), hostIp) && packet.hasHeader(tcp)) {
                result.add(packet);
            }
        }
        return result;
    }

    public List<JPacket> getTcpPacketTo(byte[] hostIp) {
        final Tcp tcp = new Tcp();
        final Ip4 ip = new Ip4();

        List<JPacket> result = new ArrayList<>();
        for (JPacket packet : getReverseFlow()) {
            if (packet.hasHeader(ip) && Arrays.equals(ip.destination(), hostIp) && packet.hasHeader(tcp)) {
                result.add(packet);
            }
        }
        return result;
    }

    public List<JPacket> getAllFlow() {
        List<JPacket> result = new ArrayList<>();
        for (Map.Entry<JFlowKey, JFlow> entrySet : getAllPacketFlow().entrySet()) {
            JFlowKey key = entrySet.getKey();
            JFlow flow = entrySet.getValue();
            result.addAll(flow.getAll());
        }
        return result;
    }

    public void openOfflineCapture() {
        StringBuilder errbuf = new StringBuilder();
        this.pcap = Pcap.openOffline(this.inputFile, errbuf);
    }

    public void closeOfflineCapture() {
        this.pcap.close();
    }

    public void addByteToArray(byte[] bytesToAdd) throws IOException {

        if (byteArrayOutputStream == null) {
            byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(bytesToAdd);
        } else {
            byteArrayOutputStream.write(bytesToAdd);
        }
    }

    private void saveAndCloseOutputFile() throws FileNotFoundException, IOException {
        try {
            if (this.fileOutputStream != null && byteArrayOutputStream != null && byteArrayOutputStream.size() > 0) {
                byteArrayOutputStream.writeTo(this.fileOutputStream);
                byteArrayOutputStream.reset();
            }
        } catch (IOException ioe) {
            System.out.println("Error saving file" + ioe.getMessage());
        } finally {
            this.fileOutputStream.close();
        }
    }

    private void newOutputFile(String name) throws FileNotFoundException, IOException {
        String fileName = this.fileOutputPath + System.currentTimeMillis() + ".out";
        if (name != null && !name.isEmpty()) {
            fileName = this.fileOutputPath + name;
        }
        try {
            this.fileOutputStream = new FileOutputStream(fileName);
            if (byteArrayOutputStream != null) {
                byteArrayOutputStream.reset();
            }
        } catch (IOException ioe) {
            System.out.println("Error creating file" + ioe.getMessage());
        }
    }

    private String getFileMimeType(byte[] initBytes) {
        Tika tika = new Tika();
        String type = tika.detect(initBytes);
        //System.out.println("Tipo de arquivo: " + type);
        return type;
    }

    private String getFileExtension(String mimeType) {
        return ".".concat(mimeType.split("/")[1]);
    }

    private boolean isTypesToSave(String fileType) {
        return fileTypeToSaveList.contains(fileType);
    }
}
