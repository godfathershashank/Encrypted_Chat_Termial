package chat;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ChatClient {
    // cache normalized -> PublicKey
    private static final Map<String, PublicKeyHolder> pubKeyCache = new ConcurrentHashMap<>();
    // ANSI color codes
    private static final String[] COLORS = {
        "\u001B[31m", // red
        "\u001B[32m", // green
        "\u001B[33m", // yellow
        "\u001B[34m", // blue
        "\u001B[35m", // magenta
        "\u001B[36m"  // cyan
    };
    private static final String RESET = "\u001B[0m";

    private static class PublicKeyHolder {
        final String displayName;
        final java.security.PublicKey key;
        PublicKeyHolder(String displayName, java.security.PublicKey key) {
            this.displayName = displayName;
            this.key = key;
        }
    }

    // connection state
    private volatile boolean connected = false;
    private Socket socket = null;
    private BufferedReader in = null;
    private PrintWriter out = null;

    public static void main(String[] args) {
        String displayName = null;
        try {
            if (args.length >= 1) {
                displayName = args[0].trim();
            } else {
                System.out.print("Enter username: ");
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                displayName = br.readLine().trim();
            }
            if (displayName == null || displayName.isEmpty()) {
                System.out.println("Username cannot be empty. Exiting.");
                return;
            }

            // passphrase: allow CLI arg (args[1]) or env var CHAT_PASSPHRASE fallback
            String pass = null;
            if (args.length >= 2) {
                pass = args[1];
            } else {
                String envPass = System.getenv("CHAT_PASSPHRASE");
                if (envPass != null && !envPass.isEmpty()) pass = envPass;
            }

            if (pass == null) {
                Console console = System.console();
                if (console != null) {
                    char[] pw = console.readPassword("Enter passphrase to unlock/create key for '%s': ", displayName);
                    pass = new String(pw);
                } else {
                    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                    System.out.print("Enter passphrase to unlock/create key for '" + displayName + "': ");
                    pass = br.readLine();
                }
            }

            if (pass == null || pass.isEmpty()) {
                System.out.println("Passphrase required. Exiting.");
                return;
            }

            ChatClient client = new ChatClient();
            client.runClient(displayName, pass);

        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void runClient(String displayName, String passphrase) throws Exception {
        String normalized = displayName.toLowerCase();

        // load or create persistent keypair (local file encrypted with pass)
        KeyPair kp = KeyManager.loadOrCreateWithPass(normalized, passphrase);
        PrivateKey myPriv = kp.getPrivate();
        PublicKey myPub = kp.getPublic();
        String myPubB64 = Encryptor.publicKeyToBase64(myPub);

        // Connect to server
        socket = new Socket("localhost", Config.PORT);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        connected = true;

        // Ensure cleanup on Ctrl+C
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));

        // Register (server creates user if not exists; rejects if existing user's pubkey differs)
        out.println("REGISTER:" + displayName + ":" + myPubB64);
        String resp = in.readLine();
        if (resp == null) {
            System.out.println("Server closed connection.");
            shutdown();
            return;
        }
        if (resp.startsWith("ERROR:")) {
            System.out.println("Registration failed: " + resp);
            shutdown();
            return;
        } else if (resp.equals("REGISTERED")) {
            System.out.println("Registered successfully as " + displayName);
        } else {
            System.out.println("Server says: " + resp);
        }

        // Reader thread: handles PUB, LIST, MSGFROM, SENT, SAVED, ERROR
        Thread reader = new Thread(() -> {
            try {
                String line;
                while (connected && (line = in.readLine()) != null) {
                    if (line.startsWith("PUB:")) {
                        String[] p = line.split(":", 3);
                        if (p.length == 3) {
                            String dname = p[1];
                            String keyB64 = p[2];
                            String norm = dname.toLowerCase();
                            try {
                                java.security.PublicKey pk = Encryptor.publicKeyFromBase64(keyB64);
                                pubKeyCache.put(norm, new PublicKeyHolder(dname, pk));
                                System.out.println("[PK] Cached public key for " + dname);
                            } catch (Exception ex) {
                                System.out.println("[PK] Failed to parse public key for " + dname);
                            }
                        }
                    } else if (line.startsWith("LIST:")) {
                        String rest = line.substring("LIST:".length());
                        System.out.println("Online: " + rest);
                    } else if (line.startsWith("MSGFROM:")) {
                        String[] p = line.split(":", 5);
                        if (p.length == 5) {
                            String senderDisplay = p[1];
                            String encKeyB64 = p[2];
                            String ivB64 = p[3];
                            String cipherB64 = p[4];
                            try {
                                byte[] encKey = Encryptor.fromBase64(encKeyB64);
                                byte[] aesKeyBytes = Encryptor.rsaDecrypt(encKey, myPriv);
                                SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
                                byte[] iv = Encryptor.fromBase64(ivB64);
                                byte[] cipher = Encryptor.fromBase64(cipherB64);
                                byte[] plain = Encryptor.aesGcmDecrypt(iv, cipher, aesKey);
                                String message = new String(plain, StandardCharsets.UTF_8);
                                System.out.println(colorize(senderDisplay) + senderDisplay + RESET + " -> " + message);
                            } catch (IllegalArgumentException iae) {
                                System.out.println("[MSG] Invalid Base64 data from " + senderDisplay);
                            } catch (Exception ex) {
                                System.out.println("[MSG] Failed to decrypt incoming message from " + senderDisplay);
                            }
                        }
                    } else if (line.startsWith("SENT:")) {
                        System.out.println("[Ack] " + line.substring("SENT:".length()));
                    } else if (line.startsWith("SAVED:")) {
                        String who = line.substring("SAVED:".length());
                        System.out.println("[Saved Offline] " + who);
                    } else if (line.startsWith("ERROR:")) {
                        System.out.println(line);
                    } else {
                        System.out.println("[Server] " + line);
                    }
                }
            } catch (IOException ioe) {
                if (connected) {
                    System.out.println("Disconnected from server: " + ioe.getMessage());
                }
            } finally {
                // Ensure full process exit so writer loop doesn't hang waiting for input
                shutdown();
                // ensure JVM exits so console doesn't become weirdly unresponsive
                System.exit(0);
            }
        }, "ReaderThread");
        reader.setDaemon(true);
        reader.start();

        // Writer loop (user input)
        System.out.println("Commands: @username message | GETPUB username | LIST | /quit");
        Scanner sc = new Scanner(System.in);
        while (connected) {
            try {
                if (!sc.hasNextLine()) break; // EOF
                String line = sc.nextLine().trim();
                if (line.isEmpty()) continue;
                if (line.equalsIgnoreCase("/quit")) {
                    out.println("/quit"); // optional notify (server ignores)
                    shutdown();
                    break;
                }
                if (line.equalsIgnoreCase("LIST")) {
                    out.println("LIST");
                    continue;
                }
                if (line.toUpperCase().startsWith("GETPUB ")) {
                    String target = line.substring(7).trim().toLowerCase();
                    out.println("GETPUB:" + target);
                    continue;
                }

                if (line.startsWith("@")) {
                    int spaceIdx = line.indexOf(' ');
                    if (spaceIdx == -1) {
                        System.out.println("Invalid format. Use: @username message");
                        continue;
                    }
                    String targetDisplay = line.substring(1, spaceIdx).trim();
                    String targetNorm = targetDisplay.toLowerCase();
                    String msg = line.substring(spaceIdx + 1);

                    PublicKeyHolder holder = pubKeyCache.get(targetNorm);
                    if (holder == null) {
                        out.println("GETPUB:" + targetNorm);
                        int attempts = 0;
                        while (attempts < 20 && (holder = pubKeyCache.get(targetNorm)) == null) {
                            Thread.sleep(100);
                            attempts++;
                        }
                        if (holder == null) {
                            System.out.println("User public key not found for " + targetDisplay + ". Use LIST or GETPUB.");
                            continue;
                        }
                    }

                    try {
                        SecretKey aesKey = Encryptor.generateAESKey();
                        Encryptor.AesResult aesRes = Encryptor.aesGcmEncrypt(msg.getBytes(StandardCharsets.UTF_8), aesKey);
                        byte[] aesKeyBytes = aesKey.getEncoded();
                        byte[] encAesKey = Encryptor.rsaEncrypt(aesKeyBytes, holder.key);

                        String encKeyB64 = Encryptor.toBase64(encAesKey);
                        String ivB64 = Encryptor.toBase64(aesRes.iv);
                        String cipherB64 = Encryptor.toBase64(aesRes.cipherText);

                        out.println("MSG:" + targetNorm + ":" + encKeyB64 + ":" + ivB64 + ":" + cipherB64);
                    } catch (Exception ex) {
                        System.out.println("Encryption failed: " + ex.getMessage());
                    }
                    continue;
                }

                System.out.println("Unknown command. Use @username message, LIST, GETPUB <user>, /quit");
            } catch (InterruptedException ie) {
                // continue loop
            }
        }

        sc.close();
        shutdown();
    }

    private void shutdown() {
        if (!connected && socket == null) return;
        connected = false;
        System.out.println("Shutting down client...");
        try { if (in != null) in.close(); } catch (IOException ignored) {}
        try { if (out != null) out.close(); } catch (Exception ignored) {}
        try { if (socket != null && !socket.isClosed()) socket.close(); } catch (IOException ignored) {}
        System.out.println("Client shut down cleanly.");
    }

    // deterministic color per display name (simple)
    private static String colorize(String displayName) {
        int hash = Math.abs(displayName.toLowerCase().hashCode());
        return COLORS[hash % COLORS.length];
    }
}
