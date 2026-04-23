import java.io.*;
import java.net.*;

public class DnsServer {

    public static void main(String[] args) {

        try {
            // get a datagram socket
            DatagramSocket s1 = new DatagramSocket(53); // bind to port 53

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
                short newflags = (short) 0x8180;
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

                // Write answer
                response.writeByte(0xC0); // the domain name is a pointer
                response.writeByte(0x0C); // the pointer location
                response.writeShort(1); // type A
                response.writeShort(1); // class IN
                response.writeInt(24); // ttl 24
                response.writeShort(4); // data length
                // write the ip address in byte format 129.252.199.171
                response.writeByte(127);
                response.writeByte(0);
                response.writeByte(0);
                response.writeByte(1);

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
}
