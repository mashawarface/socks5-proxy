import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;

public class DnsResolver {
    private final DatagramChannel dnsChannel;
    private final Selector selector;
    private final InetSocketAddress dnsServer;
    private final Map<Integer, Pending> pending = new HashMap<>();
    private final Random random = new Random();

    static class Pending {
        final ClientConnection client;
        final int port;
        final String domain;
        Pending(ClientConnection c, int p, String d) { client = c; port = p; domain = d; }
    }

    public DnsResolver(Selector selector) throws IOException {
        this.selector = selector;
        this.dnsChannel = DatagramChannel.open();
        this.dnsChannel.configureBlocking(false);
        this.dnsChannel.bind(new InetSocketAddress(0));
        this.dnsServer = findResolver();
        this.dnsChannel.register(selector, SelectionKey.OP_READ, this);
        System.out.println("[DNS]: using resolver " + dnsServer);
    }

    private InetSocketAddress findResolver() {
        try (BufferedReader br = new BufferedReader(new FileReader("/etc/resolv.conf"))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("nameserver")) {
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 2) {
                        String addr = parts[1];
                        return new InetSocketAddress(addr, 53);
                    }
                }
            }
        } catch (IOException ignored) {}
        return new InetSocketAddress("8.8.8.8", 53);
    }

    public void resolve(String domain, ClientConnection client, int port) {
        int qid;
        do {
            qid = random.nextInt(0x10000);
        } while (pending.containsKey(qid));

        try {
            Name name = Name.fromString(domain, Name.root);
            Record question = Record.newRecord(name, Type.A, DClass.IN);
            Message query = Message.newQuery(question);
            query.getHeader().setID(qid);
            byte[] wire = query.toWire();

            pending.put(qid, new Pending(client, port, domain));
            dnsChannel.send(ByteBuffer.wrap(wire), dnsServer);
            System.out.println("[DNS]: send query id=" + qid + " for domain=" + domain);
        } catch (TextParseException e) {
            System.out.println("[DNS]: invalid domain: " + domain);
            client.sendSocksError(0x04);
        } catch (IOException e) {
            System.out.println("[DNS]: sendto error: " + e.getMessage());
            pending.remove(qid);
            client.sendSocksError(0x04);
        }
    }

    public void onReadable() {
        ByteBuffer buf = ByteBuffer.allocate(2048);
        SocketAddress addr;
        try {
            addr = dnsChannel.receive(buf);
        } catch (IOException e) {
            return;
        }
        if (addr == null) return;

        buf.flip();
        byte[] data = new byte[buf.remaining()];
        buf.get(data);

        if (data.length < 2) return;

        int qid = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);

        Pending p = pending.remove(qid);
        if (p == null) {
            System.out.println("[DNS]: got unknown id=" + qid);
            return;
        }

        System.out.println("[DNS]: got response for id=" + qid + ", domain=" + p.domain);
        if (p.client == null || p.client.getClientChannel() == null) {
            System.out.println("[DNS]: client closed before DNS reply");
            return;
        }

        try {
            Message resp = new Message(data);
            int rcode = resp.getRcode();
            if (rcode != Rcode.NOERROR) {
                System.out.println("[DNS]: resolver returned error rcode=" + rcode);
                p.client.sendSocksError(0x04);
                return;
            }

            Record[] answers = resp.getSectionArray(Section.ANSWER);
            String foundIp = null;
            if (answers != null) {
                for (Record r : answers) {
                    if (r instanceof ARecord) {
                        ARecord a = (ARecord) r;
                        foundIp = a.getAddress().getHostAddress();
                        break;
                    }
                }
            }
            if (foundIp == null) {
                System.out.println("[DNS]: no A record for " + p.domain);
                p.client.sendSocksError(0x04);
                return;
            }
            System.out.println("[DNS]: resolved " + p.domain + " -> " + foundIp);
            p.client.onDnsResolved(foundIp, p.port);
        } catch (IOException e) {
            System.out.println("[DNS]: failed to parse DNS response: " + e.getMessage());
            p.client.sendSocksError(0x04);
        }
    }
}