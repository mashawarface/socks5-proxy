public class Main {
    public static void main(String[] args) throws Exception {
        int port;
        if (args.length == 1) {
            port = Integer.parseInt(args[0]);
        } else {
            port = 12345;
        }

        SocksProxy proxy = new SocksProxy(port);
        proxy.run();
    }
}