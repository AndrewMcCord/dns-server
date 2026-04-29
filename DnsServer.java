import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class DnsServer {

    public static void main(String[] args) {
        int port = 8053;
        try {
            DatagramSocket s1 = new DatagramSocket(port);
            System.out.println("DNS Server started on port " + port);
            byte[] fakeAddr = { 127, 0, 0, 1 };

            while (true) {
                try {
                    // 1. Receive packet
                    byte[] buf = new byte[512];
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    s1.receive(packet);

                    int dnsLength = packet.getLength();
                    DataInputStream request = new DataInputStream(new ByteArrayInputStream(buf, 0, dnsLength));
                    
                    // 2. Parse Header
                    short tranID = request.readShort();
                    short flags = request.readShort();
                    short numQ = request.readShort();
                    short numA = request.readShort();
                    short numNS = request.readShort();
                    short numAR = request.readShort();

                    // 3. Read and Store the Question Section exactly as it came in
                    // This prevents alignment errors (the "bad packet" error)
                    ByteArrayOutputStream questionBuffer = new ByteArrayOutputStream();
                    int b;
                    while ((b = request.read()) != 0) {
                        questionBuffer.write(b);
                    }
                    questionBuffer.write(0); // Null terminator for domain
                    short qType = request.readShort();
                    short qClass = request.readShort();

                    String domainName = parseDomainName(buf, 12);
                    System.out.println("Request for: " + domainName);

                    // 4. Build Response Header
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    DataOutputStream response = new DataOutputStream(out);

                    response.writeShort(tranID);
                    response.writeShort((short) 0x8180); // Standard response flags
                    response.writeShort(1); // 1 Question
                    response.writeShort(1); // 1 Answer
                    response.writeShort(0);
                    response.writeShort(0);

                    // Write Question section back exactly
                    response.write(questionBuffer.toByteArray());
                    response.writeShort(qType);
                    response.writeShort(qClass);

                    // 5. Resolve IP (Fake or Upstream)
                    byte[] resolvedIp = null;
                    if (domainName.equalsIgnoreCase("www.paypal.com")) {
                        resolvedIp = fakeAddr;
                        System.out.println("  -> Returning Fake IP");
                    } else {
                        try {
                            resolvedIp = getIpFromUpstream(buf, dnsLength);
                            System.out.println("  -> Forwarded to 8.8.8.8");
                        } catch (IOException e) {
                            System.err.println("  -> Upstream Error: " + e.getMessage());
                            continue; 
                        }
                    }

                    // 6. Write Answer Section
                    response.writeByte(0xC0); // Pointer to domain name
                    response.writeByte(0x0C); // Offset 12
                    response.writeShort(1);    // Type A
                    response.writeShort(1);    // Class IN
                    response.writeInt(24);     // TTL
                    response.writeShort(4);    // Data Length
                    response.write(resolvedIp);

                    // 7. Send Packet
                    byte[] finalResponse = out.toByteArray();
                    DatagramPacket packetBack = new DatagramPacket(
                        finalResponse, 
                        finalResponse.length, 
                        packet.getAddress(), 
                        packet.getPort()
                    );
                    s1.send(packetBack);

                    request.close();
                    response.close();

                } catch (Exception e) {
                    System.err.println("Error processing packet: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("Server socket error: " + e.getMessage());
        }
    }

    private static String parseDomainName(byte[] buffer, int offset) {
        StringBuilder sb = new StringBuilder();
        int cursor = offset;
        while (true) {
            int len = buffer[cursor] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) break; 
            cursor++;
            for (int i = 0; i < len; i++) {
                sb.append((char) buffer[cursor++]);
            }
            sb.append(".");
        }
        if (sb.length() > 0) sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    private static byte[] getIpFromUpstream(byte[] requestPacket, int length) throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(2000); 
            InetAddress upstream = InetAddress.getByName("8.8.8.8");
            socket.send(new DatagramPacket(requestPacket, length, upstream, 53));

            byte[] respBuf = new byte[512];
            DatagramPacket respPacket = new DatagramPacket(respBuf, respBuf.length);
            socket.receive(respPacket);

            int cursor = 12; // Skip Header
            while (respBuf[cursor] != 0) {
                if ((respBuf[cursor] & 0xC0) == 0xC0) { cursor += 2; break; }
                cursor += (respBuf[cursor] & 0xFF) + 1;
            }
            if (respBuf[cursor] == 0) cursor++;
            cursor += 4; // Skip QType/QClass

            int numAnswers = ((respBuf[6] & 0xFF) << 8) | (respBuf[7] & 0xFF);
            for (int i = 0; i < numAnswers; i++) {
                // Skip Name
                if ((respBuf[cursor] & 0xC0) == 0xC0) { cursor += 2; } 
                else { while (respBuf[cursor] != 0) cursor += respBuf[cursor] + 1; cursor++; }

                int type = ((respBuf[cursor] & 0xFF) << 8) | (respBuf[cursor + 1] & 0xFF);
                int dataLen = ((respBuf[cursor + 8] & 0xFF) << 8) | (respBuf[cursor + 9] & 0xFF);

                if (type == 1 && dataLen == 4) { 
                    byte[] ip = new byte[4];
                    System.arraycopy(respBuf, cursor + 10, ip, 0, 4);
                    return ip;
                }
                cursor += 10 + dataLen; 
            }
        }
        throw new IOException("No A-record found");
    }
}
