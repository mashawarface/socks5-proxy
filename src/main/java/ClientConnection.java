import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;

public class ClientConnection {
    enum State {HANDSHAKE, REQUEST, WAITING_DNS, CONNECTING_UPSTREAM, RELAY, ERROR, CLOSED}

    private final SocketChannel clientChannel;
    private SocketChannel upstreamChannel; // may be null
    private final Selector selector;
    private final DnsResolver dnsResolver;

    private static final int BUFFER_CAPACITY = 64 * 1024;
    private final ByteBuffer clientToUpstream = ByteBuffer.allocate(BUFFER_CAPACITY);
    private final ByteBuffer toClient = ByteBuffer.allocate(BUFFER_CAPACITY);

    private State state = State.HANDSHAKE;
    private boolean closeAfterWrite = false;
    private boolean upstreamClosedWrite = false;
    private boolean clientClosedWrite = false;

    private int targetPort;

    public ClientConnection(SocketChannel clientChannel, Selector selector, DnsResolver dnsResolver) {
        this.clientChannel = clientChannel;
        this.selector = selector;
        this.dnsResolver = dnsResolver;
    }

    public SocketChannel getClientChannel() {
        return clientChannel;
    }

    public SocketChannel getUpstreamChannel() {
        return upstreamChannel;
    }

    public void close() {
        if (state == State.CLOSED) return;

        state = State.CLOSED;

        System.out.println("[SERVER]: close connect for " + clientAddressSafe());

        if (upstreamChannel != null) {
            SelectionKey k = upstreamChannel.keyFor(selector);
            if (k != null) k.cancel();
            try {
                upstreamChannel.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        SelectionKey k = clientChannel.keyFor(selector);
        if (k != null) k.cancel();
        try {
            clientChannel.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String clientAddressSafe() {
        SocketAddress sa = null;
        try {
            sa = clientChannel.getRemoteAddress();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return sa.toString();

    }

    private void updateClientInterest() {
        if (state == State.CLOSED) return;

        try {
            SelectionKey key = clientChannel.keyFor(selector);

            if (key == null) return;

            int ops = 0;

            if (!clientClosedWrite && (state == State.HANDSHAKE || state == State.REQUEST || state == State.RELAY)) {
                if (clientToUpstream.hasRemaining()) ops |= SelectionKey.OP_READ;
            }

            if (toClient.position() > 0) ops |= SelectionKey.OP_WRITE;

            key.interestOps(ops);
        } catch (CancelledKeyException ignored) {
        }
    }

    private void updateUpstreamInterest() {
        if (upstreamChannel == null || upstreamClosedWrite) return;

        SelectionKey key = upstreamChannel.keyFor(selector);

        if (key == null) return;

        int ops = 0;

        if (state == State.CONNECTING_UPSTREAM) ops |= SelectionKey.OP_CONNECT;

        if (state == State.RELAY) {
            if (clientToUpstream.position() > 0) ops |= SelectionKey.OP_WRITE;
            if (toClient.hasRemaining()) ops |= SelectionKey.OP_READ;
        }

        key.interestOps(ops);
    }

    private void processBuffers() {
        if (state == State.HANDSHAKE) {
            clientToUpstream.mark();
            if (clientToUpstream.remaining() < 2) {
                clientToUpstream.reset();
                return;
            }
            int ver = clientToUpstream.get() & 0xFF;

            int nmethods = clientToUpstream.get() & 0xFF;
            if (clientToUpstream.remaining() < nmethods) {
                clientToUpstream.reset();
                return;
            }

            byte[] methods = new byte[nmethods];
            clientToUpstream.get(methods);

            System.out.println("[SERVER]: handshake");

            if (toClient.remaining() < 2) {
                System.out.println("[SERVER]: toClient buffer overflow on handshake reply");
                close();
                return;
            }

            toClient.put((byte) 0x05);
            toClient.put((byte) 0x00);

            updateClientInterest();

            state = State.REQUEST;

        } else if (state == State.REQUEST) {
            clientToUpstream.mark();

            if (clientToUpstream.remaining() < 4) {
                clientToUpstream.reset();
                return;
            }

            int ver = clientToUpstream.get() & 0xFF;
            int cmd = clientToUpstream.get() & 0xFF;

            clientToUpstream.get();

            int atyp = clientToUpstream.get() & 0xFF;

            if (cmd != 0x01) {
                System.out.println("[SERVER]: unsupported CMD");
                sendSocksError(0x07);
                return;
            }

            if (atyp == 0x01) {
                if (clientToUpstream.remaining() < 6) {
                    clientToUpstream.reset();
                    return;
                }

                byte[] addr = new byte[4];
                clientToUpstream.get(addr);

                byte[] portb = new byte[2];
                clientToUpstream.get(portb);

                String ip = (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "." + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
                int port = ((portb[0] & 0xFF) << 8) | (portb[1] & 0xFF);

                System.out.println("[SERVER]: CONNECT ipv4 " + ip + ":" + port);

                startConnectUpstream(ip, port);

            } else if (atyp == 0x03) {
                if (clientToUpstream.remaining() < 1) {
                    clientToUpstream.reset();
                    return;
                }

                int ln = clientToUpstream.get() & 0xFF;
                if (clientToUpstream.remaining() < ln + 2) {
                    clientToUpstream.reset();
                    return;
                }

                byte[] nameBytes = new byte[ln];
                clientToUpstream.get(nameBytes);
                String domain = new String(nameBytes);

                byte[] portb = new byte[2];
                clientToUpstream.get(portb);
                int port = ((portb[0] & 0xFF) << 8) | (portb[1] & 0xFF);

                System.out.println("[SERVER]: CONNECT domain " + domain + ":" + port);

                state = State.WAITING_DNS;

                targetPort = port;

                dnsResolver.resolve(domain, this, port);

            } else {
                System.out.println("[SERVER]: unknown ATYP");
                sendSocksError(0x08);
            }
        }
    }

    private void startConnectUpstream(String ip, int port) {
        this.targetPort = port;

        try {
            upstreamChannel = SocketChannel.open();
            upstreamChannel.configureBlocking(false);

            boolean connected = upstreamChannel.connect(new InetSocketAddress(ip, port));

            if (connected) {
                onUpstreamConnected();
            } else {
                upstreamChannel.register(selector, SelectionKey.OP_CONNECT, this);
                state = State.CONNECTING_UPSTREAM;
            }
        } catch (IOException e) {
            System.out.println("[SERVER]: upstream connect failed " + e.getMessage());
            sendSocksError(0x04);
        }
    }

    public void onDnsResolved(String ip, int port) {
        if (state != State.WAITING_DNS) {
            System.out.println("[SERVER]: unexpected DNS reply");
            return;
        }

        startConnectUpstream(ip, port);
    }

    public void onUpstreamConnectable() {
        if (upstreamChannel == null) return;

        try {
            if (upstreamChannel.finishConnect()) {
                onUpstreamConnected();
            }
        } catch (IOException e) {
            System.out.println("[SERVER]: upstream connect failed " + e.getMessage());
            sendSocksError(0x05);
        }
    }

    private void onUpstreamConnected() {
        // VER(5) REP(0) RSV(0) ATYP(1) BND.ADDR(0.0.0.0) BND.PORT(0)
        byte[] reply = new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        if (toClient.remaining() < reply.length) {
            System.out.println("[SERVER]: toClient buffer overflow on reply");
            sendSocksError(0x01);
            return;
        }

        toClient.put(reply);
        updateClientInterest();
        System.out.println("[SERVER]: CONNECT OK");

        try {
            if (upstreamChannel.keyFor(selector) == null) {
                upstreamChannel.register(selector, SelectionKey.OP_READ, this);
            } else {
                updateUpstreamInterest();
            }
            state = State.RELAY;
        } catch (IOException e) {
            sendSocksError(0x05);
        }
    }

    public void onUpstreamReadable() {
        if (upstreamChannel == null) return;
        try {
            int r = upstreamChannel.read(toClient);

            if (r == -1) {
                System.out.println("[SERVER]: upstream closed");
                upstreamClosedWrite = true;

                SelectionKey k = upstreamChannel.keyFor(selector);
                if (k != null) k.interestOps(0);

                if (toClient.position() == 0 && clientToUpstream.position() == 0) {
                    close();
                } else {
                    updateClientInterest();
                }

                return;
            }
            if (r > 0) {
                updateClientInterest();
                updateUpstreamInterest();
            }
        } catch (IOException e) {
            upstreamClosedWrite = true;
            updateClientInterest();
        }
    }

    public void onUpstreamWritable() {
        if (upstreamChannel == null) return;
        if (state == State.CONNECTING_UPSTREAM) return;

        if (state == State.RELAY) {
            clientToUpstream.flip();

            try {
                while (clientToUpstream.hasRemaining()) {
                    int written = upstreamChannel.write(clientToUpstream);
                    if (written == 0) break;
                }

                if (clientClosedWrite && clientToUpstream.position() == 0) {
                    upstreamChannel.shutdownOutput();
                }
            } catch (IOException e) {
                close();
                return;
            } finally {
                clientToUpstream.compact();
            }

            updateUpstreamInterest();
            updateClientInterest();
        }
    }

    public void onClientReadable() {
        if (state == State.CLOSED) return;

        try {
            int r = clientChannel.read(clientToUpstream);

            if (r == -1) {
                System.out.println("[SERVER]: Client closed " + clientAddressSafe());
                clientClosedWrite = true;

                SelectionKey k = clientChannel.keyFor(selector);
                if (k != null) k.interestOps(0);

                if (toClient.position() == 0 && clientToUpstream.position() == 0) {
                    close();
                } else {
                    updateUpstreamInterest();
                }

                return;
            }

            if (r == 0) return;
        } catch (IOException e) {
            System.out.println("[SERVER]: Client reset " + clientAddressSafe());
            close();
            return;
        }

        if (state == State.HANDSHAKE || state == State.REQUEST) {
            clientToUpstream.flip();
            processBuffers();
            clientToUpstream.compact();
        } else if (state == State.RELAY) {
            updateUpstreamInterest();
        }
        updateClientInterest();
    }

    public void onClientWritable() {
        if (state == State.CLOSED) return;
        try {
            toClient.flip();
            try {
                while (toClient.hasRemaining()) {
                    int written = clientChannel.write(toClient);
                    if (written == 0) break;
                }

                if (upstreamClosedWrite && toClient.position() == 0) {
                    clientChannel.shutdownOutput();
                }
            } finally {
                toClient.compact();
            }

            if (toClient.position() == 0 && closeAfterWrite && state == State.ERROR) {
                close();
                return;
            }

            if (toClient.position() == 0 && clientToUpstream.position() == 0 &&
                    (clientClosedWrite || upstreamClosedWrite)) {
                close();
                return;
            }

            updateClientInterest();
            updateUpstreamInterest();
        } catch (IOException e) {
            close();
        }
    }

    void sendSocksError(int rep) {
        byte[] reply = new byte[]{0x05, (byte) rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0};

        if (toClient.remaining() < reply.length) {
            System.out.println("[SERVER]: toClient buffer overflow on error reply");
            close();
            return;
        }

        toClient.put(reply);

        closeAfterWrite = true;

        state = State.ERROR;

        updateClientInterest();
    }
}