import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class DnsServer {

    public static void main(String[] args) {
        // Port 53 is mandatory for a system-wide DNS
        int port = 53;
        try {
            DatagramSocket serverSocket = new DatagramSocket(port);
            System.out.println("DNS Server active on port " + port);
            byte[] fakeAddr = { 127, 0, 0, 1 };

            while (true) {
                try {
                    byte[] buf = new byte[1024]; // Larger buffer for modern DNS
                    DatagramPacket clientPacket = new DatagramPacket(buf, buf.length);
                    serverSocket.receive(clientPacket);

                    int dnsLength = clientPacket.getLength();
                    String domainName = parseDomainName(buf, 12);

                    if (domainName.isEmpty())
                        continue;

                    // Logic: Spoof PayPal, Forward everything else
                    if (domainName.toLowerCase().contains("paypal.com")) {
                        System.out.println("SPOOFING: " + domainName);
                        sendFakeResponse(serverSocket, clientPacket, buf, fakeAddr);
                    } else {
                        System.out.println("FORWARDING: " + domainName);
                        forwardRequest(serverSocket, clientPacket, buf, dnsLength);
                    }

                } catch (Exception e) {
                    System.err.println("Packet error: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println(e);
        }
    }

    // Proxy the exact packet to 8.8.8.8 and back to the client
    private static void forwardRequest(DatagramSocket serverSocket, DatagramPacket clientPacket, byte[] query, int len)
            throws IOException {
        try (DatagramSocket upstreamSocket = new DatagramSocket()) {
            upstreamSocket.setSoTimeout(2000);
            InetAddress googleDns = InetAddress.getByName("8.8.8.8");

            // Send client's query to Google
            upstreamSocket.send(new DatagramPacket(query, len, googleDns, 53));

            // Get Google's response
            byte[] responseBuf = new byte[1024];
            DatagramPacket upstreamPacket = new DatagramPacket(responseBuf, responseBuf.length);
            upstreamSocket.receive(upstreamPacket);

            // Send Google's exact response back to the browser
            serverSocket.send(new DatagramPacket(
                    responseBuf,
                    upstreamPacket.getLength(),
                    clientPacket.getAddress(),
                    clientPacket.getPort()));
        }
    }

    private static void sendFakeResponse(DatagramSocket socket, DatagramPacket request, byte[] reqBuf, byte[] ip)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream res = new DataOutputStream(out);

        // 1. Header
        res.write(reqBuf, 0, 2); // Transaction ID
        res.writeShort(0x8180); // Flags
        res.writeShort(1); // 1 Question
        res.writeShort(1); // 1 Answer
        res.writeShort(0); // 0 Authority
        res.writeShort(0); // 0 Additional

        // 2. Question Section (ECHO the request exactly)
        int cursor = 12;
        while (reqBuf[cursor] != 0)
            res.writeByte(reqBuf[cursor++]);
        res.writeByte(0); // End of Name

        // Read the type and class the user actually asked for and write them back
        short qType = (short) ((reqBuf[++cursor] << 8) | (reqBuf[++cursor] & 0xFF));
        short qClass = (short) ((reqBuf[++cursor] << 8) | (reqBuf[++cursor] & 0xFF));
        res.writeShort(qType);
        res.writeShort(qClass);

        // 3. Answer Section
        res.writeShort(0xc00c); // Pointer to name
        res.writeShort(1); // We always return Type A (IPv4)
        res.writeShort(1); // Class IN
        res.writeInt(60); // TTL
        res.writeShort(4); // Data Length
        res.write(ip); // 127.0.0.1

        byte[] finalData = out.toByteArray();
        socket.send(new DatagramPacket(finalData, finalData.length, request.getAddress(), request.getPort()));
    }

    private static String parseDomainName(byte[] buffer, int offset) {
        StringBuilder sb = new StringBuilder();
        int cursor = offset;
        try {
            while (buffer[cursor] != 0) {
                int len = buffer[cursor] & 0xFF;
                if ((len & 0xC0) == 0xC0)
                    break; // End on pointer
                cursor++;
                for (int i = 0; i < len; i++)
                    sb.append((char) buffer[cursor++]);
                sb.append(".");
            }
        } catch (Exception e) {
            return "";
        }
        return sb.length() > 0 ? sb.substring(0, sb.length() - 1) : "";
    }
}
