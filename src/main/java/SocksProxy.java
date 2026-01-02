import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.*;
import java.util.Iterator;
import java.util.Set;

public class SocksProxy {
    private final int port;

    public SocksProxy(int port) {
        this.port = port;
    }

    public void run() throws IOException {
        Selector selector = Selector.open();

        ServerSocketChannel server = ServerSocketChannel.open();
        server.bind(new InetSocketAddress("0.0.0.0", port));
        server.configureBlocking(false);
        server.register(selector, SelectionKey.OP_ACCEPT, null);
        System.out.println("[SERVER]: Listening on 0.0.0.0:" + port);

        DnsResolver dnsResolver = new DnsResolver(selector);

        try {
            while (true) {
                selector.select();

                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> it = keys.iterator();

                while (it.hasNext()) {
                    SelectionKey key = it.next();
                    it.remove();

                    if (!key.isValid()) continue;

                    try {
                        if (key.channel() == server && key.isAcceptable()) {
                            SocketChannel clientCh = server.accept();
                            if (clientCh == null) continue;

                            clientCh.configureBlocking(false);
                            System.out.println("[SERVER]: New connection from " + clientCh.getRemoteAddress());

                            ClientConnection client = new ClientConnection(clientCh, selector, dnsResolver);
                            clientCh.register(selector, SelectionKey.OP_READ, client);
                            continue;
                        }

                        Object attachment = key.attachment();

                        if (attachment instanceof DnsResolver) {
                            DnsResolver dr = (DnsResolver) attachment;
                            if (key.isReadable()) {
                                try {
                                    dr.onReadable();
                                } catch (CancelledKeyException ignored) {
                                }
                            }
                            continue;
                        }

                        if (attachment instanceof ClientConnection) {
                            ClientConnection client = (ClientConnection) attachment;

                            try {
                                if (key.channel() == client.getClientChannel()) {
                                    if (key.isReadable()) client.onClientReadable();
                                    if (key.isWritable()) client.onClientWritable();
                                } else if (client.getUpstreamChannel() != null
                                        && key.channel() == client.getUpstreamChannel()) {
                                    if (key.isReadable()) client.onUpstreamReadable();
                                    if (key.isWritable()) client.onUpstreamWritable();
                                    if (key.isConnectable()) client.onUpstreamConnectable();
                                }
                            } catch (CancelledKeyException ignored) {
                            }
                        }
                    } catch (CancelledKeyException ignoredOuter) {
                    }
                }
            }
        } finally {
            System.out.println("[SERVER]: Shutdown");
            try {
                server.close();
            } catch (Exception ignored) {
            }
            try {
                selector.close();
            } catch (Exception ignored) {
            }
        }
    }
}
