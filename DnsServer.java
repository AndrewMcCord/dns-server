import java.io.*;
import java.net.*;

public class DnsServer {

    public static void main(String[] args) {

        try {
            // get a datagram socket
            DatagramSocket s1 = new DatagramSocket(8053); // bind to port 53
            byte[] fakeAddr = { 127, 0, 0, 1 };

            for (int i = 0; i < 500; i++) {

                // receive a packet
                byte[] buf = new byte[256];
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                s1.receive(packet);

                // parse the packet by putting the data in datainputstream
                int dnsLength = packet.getLength();
                int dnsRLength = dnsLength + 16;
                System.out.println("request Length " + dnsLength);

                DataInputStream request = new DataInputStream(new ByteArrayInputStream(buf, 0, dnsLength));
                ByteArrayOutputStream out = new ByteArrayOutputStream(dnsRLength);
                DataOutputStream response = new DataOutputStream(out);

                // Read Field
                short tranID = request.readShort();
                short flags = request.readShort();
                short numQ = request.readShort();
                short numA = request.readShort();
                short numAR = request.readShort();
                short numARR = request.readShort();

                // Write Field
                response.writeShort(tranID);
                short newflags = (short) 0x8180; // TODO: last nibble of flags should be response code, so if rq type is
                                                 // wrong it should be an error
                response.writeShort(newflags);
                response.writeShort(1);
                response.writeShort(1);
                response.writeShort(0);
                response.writeShort(0);

                // Read Question
                int qL = dnsLength - 12;
                byte[] Q = new byte[qL];
                request.read(Q, 0, qL);

                // Write question
                response.write(Q, 0, qL);
                String domainName = parseDomainName(buf, 12);

                // Write answer
                response.writeByte(0xC0); // the domain name is a pointer
                response.writeByte(0x0C); // the pointer location
                response.writeShort(1); // type A
                response.writeShort(1); // class IN
                response.writeInt(24); // ttl 24
                response.writeShort(4); // data length
                // write the ip address in byte format
                if (domainName.equals("www.paypal.com")) {
                    response.write(fakeAddr);
                } else {
                    try {
                        byte[] realIp = getIpFromUpstream(buf, dnsLength);
                        response.write(realIp);
                    } catch (Exception e) {
                        System.out.println(e.getMessage());
                    }
                }

                // close
                request.close();
                response.close();

                // construct datagram packet
                DatagramPacket packetback = new DatagramPacket(out.toByteArray(), dnsRLength, packet.getAddress(),
                        packet.getPort());

                // send a packet
                s1.send(packetback);

            }
            s1.close();
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private static String parseDomainName(byte[] buffer, int offset) {
        StringBuilder sb = new StringBuilder();
        int cursor = offset;

        while (true) {
            // 1. Get length of the next label (mask with 0xFF to treat as unsigned)
            int len = buffer[cursor] & 0xFF;

            // 2. A null byte (0x00) signifies the end of the domain name
            if (len == 0) {
                break;
            }

            // 3. Optional: Handle Pointers (0xC0 indicates start of a pointer)
            if ((len & 0xC0) == 0xC0) {
                // Pointer logic: The address is a 14-bit integer formed by the next two bytes
                // You would jump to that location in the buffer to continue parsing.
                // For simple non-compressed queries, you may not need this.
                break;
            }

            // 4. Move past the length byte to the characters
            cursor++;

            // 5. Read the label characters
            for (int i = 0; i < len; i++) {
                sb.append((char) buffer[cursor++]);
            }

            // 6. Append a dot after the label
            sb.append(".");
        }

        // Remove the trailing dot if one was added
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
        }

        return sb.toString();
    }

    private static byte[] getIpFromUpstream(byte[] requestPacket, int length) throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress upstream = InetAddress.getByName("8.8.8.8");
            socket.send(new DatagramPacket(requestPacket, length, upstream, 53));

            byte[] respBuf = new byte[512];
            DatagramPacket respPacket = new DatagramPacket(respBuf, respBuf.length);
            socket.receive(respPacket);

            // 1. Skip the 12-byte header
            int cursor = 12;

            // 2. Skip the Question Section (the labels)
            // Labels are length-prefixed, ending with a null byte (0x00)
            while (respBuf[cursor] != 0) {
                // Check for potential compression pointers in the question (0xC0)
                if ((respBuf[cursor] & 0xC0) == 0xC0) {
                    cursor += 2; // Pointers are 2 bytes
                    break;
                }
                // Move cursor past the length byte + the label length
                cursor += (respBuf[cursor] & 0xFF) + 1;
            }
            // Move past the final null byte of the domain name
            if (respBuf[cursor] == 0) {
                cursor++;
            }

            // 3. Skip the Type (2) and Class (2) fields of the question
            cursor += 4;

            // 4. NOW start scanning for the Answer section
            for (int i = cursor; i < respPacket.getLength() - 4; i++) {
                // Look for Type A (0x0001) + Class IN (0x0001)
                if (respBuf[i] == 0 && respBuf[i + 1] == 1 && respBuf[i + 2] == 0 && respBuf[i + 3] == 1) {
                    // Found the Answer record header.
                    // Skip Type(2), Class(2), TTL(4), RDLength(2) = 10 bytes
                    int ipStart = i + 10;

                    // Safety check: ensure we aren't reading past the buffer
                    if (ipStart + 4 <= respPacket.getLength()) {
                        byte[] ip = new byte[4];
                        System.arraycopy(respBuf, ipStart, ip, 0, 4);
                        return ip;
                    }
                }
            }
        }
        throw new IOException("Could not find IP in upstream response");
    }
}
