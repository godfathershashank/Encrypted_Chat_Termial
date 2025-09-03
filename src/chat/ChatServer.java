package chat;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class ChatServer {

    // online map: normalized -> PrintWriter
    private static final ConcurrentMap<String, PrintWriter> clients = new ConcurrentHashMap<>();

    private static volatile boolean running = true;
    private static ServerSocket serverSocket = null;

    public static void main(String[] args) {
        try {
            System.out.println("Starting server, initializing DB...");
            DB.init("chat.db");
            System.out.println("DB ready. Listening on port " + Config.PORT);

            // Add JVM shutdown hook to ensure cleanup on Ctrl+C / kill
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("Shutdown hook triggered.");
                shutdown();
            }));

            // Start admin console reader in its own thread (safe & robust)
            Thread adminThread = new Thread(() -> adminConsole());
            adminThread.setDaemon(true);
            adminThread.start();

            serverSocket = new ServerSocket(Config.PORT);
            while (running) {
                try {
                    Socket s = serverSocket.accept();
                    new Thread(new ClientHandler(s)).start();
                } catch (SocketException se) {
                    // Occurs when serverSocket is closed during shutdown
                    if (!running) break;
                    System.err.println("SocketException in accept(): " + se.getMessage());
                }
            }

            System.out.println("Server main loop exiting.");
        } catch (BindException be) {
            System.err.println("Port already in use: " + be.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            shutdown();
        }
    }

    // Admin console: read lines from STDIN, handle /shutdown
    private static void adminConsole() {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
            String line;
            while (running) {
                // readLine blocks until input or EOF
                line = br.readLine();
                if (line == null) {
                    // no more input (EOF). Sleep briefly and continue loop so server doesn't exit abruptly.
                    try { Thread.sleep(200); } catch (InterruptedException ignored) {}
                    continue;
                }
                line = line.trim();
                if (line.equalsIgnoreCase("/shutdown") || line.equalsIgnoreCase("/quit")) {
                    System.out.println("Admin requested shutdown.");
                    shutdown();
                    break;
                } else if (line.equalsIgnoreCase("/clients")) {
                    System.out.println("Connected clients: " + clients.keySet());
                } else if (!line.isEmpty()) {
                    System.out.println("Unknown admin command: " + line + " (use /shutdown or /clients)");
                }
            }
        } catch (IOException ioe) {
            // If STDIN closed, just log and return
            System.out.println("Admin console input closed.");
        }
    }

    public static synchronized void shutdown() {
        if (!running) return;
        running = false;
        System.out.println("Shutting down server...");

        // Close server socket so accept() will stop
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException ignored) {}

        // Notify and close all client writers
        for (Map.Entry<String, PrintWriter> e : clients.entrySet()) {
            try {
                PrintWriter pw = e.getValue();
                if (pw != null) {
                    pw.println("SERVER: Server shutting down...");
                    pw.flush();
                    pw.close();
                }
            } catch (Exception ignored) {}
        }
        clients.clear();

        // Attempt to close DB (if implemented)
        try {
            DB.close();
        } catch (Throwable t) {
            // DB.close may not exist in older code; ignore
        }

        System.out.println("Server shutdown complete.");
    }

    private static class ClientHandler implements Runnable {
        private final Socket socket;
        private String normalized = null;
        private PrintWriter out;

        ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (
                Socket s = socket;
                BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
                PrintWriter outLocal = new PrintWriter(s.getOutputStream(), true)
            ) {
                this.out = outLocal;

                // Expect: REGISTER:<displayName>:<pubKeyBase64>
                String first = in.readLine();
                if (first == null || !first.startsWith("REGISTER:")) {
                    outLocal.println("ERROR:Expected REGISTER:<username>:<pubkeyBase64>");
                    return;
                }
                String[] reg = first.split(":", 3);
                if (reg.length < 3) {
                    outLocal.println("ERROR:Bad REGISTER format");
                    return;
                }
                String display = reg[1].trim();
                String pubKeyB64 = reg[2].trim();
                if (display.isEmpty() || pubKeyB64.isEmpty()) {
                    outLocal.println("ERROR:Empty username or public key");
                    return;
                }
                normalized = display.toLowerCase();

                // If user exists, ensure pubkey matches; else create user
                if (DB.userExists(normalized)) {
                    String storedPub = DB.getPublicKey(normalized);
                    if (!storedPub.equals(pubKeyB64)) {
                        outLocal.println("ERROR:USERNAME_TAKEN");
                        return;
                    }
                } else {
                    // create new user entry with this pubkey
                    DB.createUser(normalized, display, pubKeyB64);
                }

                // put online (reject if someone already online with same normalized)
                if (clients.putIfAbsent(normalized, outLocal) != null) {
                    outLocal.println("ERROR:USERNAME_TAKEN");
                    return;
                }

                System.out.println("User registered/online: " + display + " from " + s.getRemoteSocketAddress());
                outLocal.println("REGISTERED");

                // deliver queued messages
                List<DB.MessageRow> pending = DB.getUndeliveredMessages(normalized);
                if (!pending.isEmpty()) {
                    for (DB.MessageRow m : pending) {
                        String forward = "MSGFROM:" + m.sender + ":" + m.encKeyB64 + ":" + m.ivB64 + ":" + m.cipherB64;
                        outLocal.println(forward);
                        DB.markDelivered(m.id);
                    }
                }

                String line;
                while (running && (line = in.readLine()) != null) {
                    if (line.equalsIgnoreCase("LIST")) {
                        List<String> online = new ArrayList<>();
                        for (String u : clients.keySet()) {
                            String disp = DB.getDisplayName(u);
                            online.add(disp);
                        }
                        Collections.sort(online, String.CASE_INSENSITIVE_ORDER);
                        outLocal.println("LIST:" + String.join(",", online));
                        continue;
                    }

                    if (line.startsWith("GETPUB:")) {
                        String[] p = line.split(":", 2);
                        if (p.length < 2) { outLocal.println("ERROR:GETPUB bad format"); continue; }
                        String targetNorm = p[1].trim().toLowerCase();
                        String keyB64 = DB.getPublicKey(targetNorm);
                        String targetDisplay = DB.getDisplayName(targetNorm);
                        if (keyB64 == null) {
                            outLocal.println("ERROR:User not found: " + targetNorm);
                        } else {
                            outLocal.println("PUB:" + targetDisplay + ":" + keyB64);
                        }
                        continue;
                    }

                    if (line.startsWith("MSG:")) {
                        String[] p = line.split(":", 5);
                        if (p.length < 5) { outLocal.println("ERROR:MSG bad format"); continue; }
                        String targetNorm = p[1].trim().toLowerCase();
                        String encKeyB64  = p[2];
                        String ivB64      = p[3];
                        String cipherB64  = p[4];
                        String senderDisplay = DB.getDisplayName(normalized);

                        // store message (delivered=false initially). If target online, forward & mark delivered.
                        int msgId = DB.storeMessage(targetNorm, senderDisplay, encKeyB64, ivB64, cipherB64, false);
                        PrintWriter targetOut = clients.get(targetNorm);
                        if (targetOut != null) {
                            // forward now
                            targetOut.println("MSGFROM:" + senderDisplay + ":" + encKeyB64 + ":" + ivB64 + ":" + cipherB64);
                            DB.markDelivered(msgId);
                            outLocal.println("SENT:" + targetNorm);
                        } else {
                            outLocal.println("SAVED:" + targetNorm);
                        }
                        continue;
                    }

                    outLocal.println("ERROR:Unknown command");
                }

            } catch (IOException ioe) {
                System.out.println("I/O for user " + normalized + ": " + ioe.getMessage());
            } catch (Exception ex) {
                System.out.println("Unexpected error for user " + normalized + ": " + ex.getMessage());
                ex.printStackTrace();
            } finally {
                if (normalized != null) {
                    clients.remove(normalized);
                    System.out.println("User disconnected: " + normalized);
                }
                try { socket.close(); } catch (IOException ignored) {}
            }
        }
    }
}
