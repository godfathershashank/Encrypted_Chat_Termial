package chat;

import java.sql.*;
import java.util.*;

public class DB {
    private static Connection conn;

    public static void init(String dbFilePath) throws Exception {
        Class.forName("org.sqlite.JDBC");
        conn = DriverManager.getConnection("jdbc:sqlite:" + dbFilePath);
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA foreign_keys = ON;");
            st.execute("CREATE TABLE IF NOT EXISTS users (" +
                    "username TEXT PRIMARY KEY," +
                    "displayName TEXT," +
                    "pubKeyB64 TEXT)");
            st.execute("CREATE TABLE IF NOT EXISTS messages (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "recipient TEXT," +
                    "sender TEXT," +
                    "encKeyB64 TEXT," +
                    "ivB64 TEXT," +
                    "cipherB64 TEXT," +
                    "timestamp INTEGER," +
                    "delivered INTEGER DEFAULT 0)");
        }
    }

    public static synchronized void close() {
        try {
            if (conn != null && !conn.isClosed()) {
                conn.close();
                conn = null;
                System.out.println("DB connection closed.");
            }
        } catch (SQLException e) {
            System.err.println("DB close failed: " + e.getMessage());
        }
    }

    public static synchronized boolean userExists(String username) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    public static synchronized void createUser(String username, String displayName, String pubKeyB64) throws SQLException {
        String sql = "INSERT INTO users(username, displayName, pubKeyB64) VALUES(?,?,?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, displayName);
            ps.setString(3, pubKeyB64);
            ps.executeUpdate();
        }
    }

    public static synchronized String getPublicKey(String username) throws SQLException {
        String sql = "SELECT pubKeyB64 FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getString("pubKeyB64");
                return null;
            }
        }
    }

    public static synchronized String getDisplayName(String username) throws SQLException {
        String sql = "SELECT displayName FROM users WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getString("displayName");
                return username;
            }
        }
    }

    public static synchronized int storeMessage(String recipient, String sender, String encKeyB64, String ivB64, String cipherB64, boolean delivered) throws SQLException {
        String sql = "INSERT INTO messages(recipient, sender, encKeyB64, ivB64, cipherB64, timestamp, delivered) VALUES(?,?,?,?,?,?,?)";
        try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, recipient);
            ps.setString(2, sender);
            ps.setString(3, encKeyB64);
            ps.setString(4, ivB64);
            ps.setString(5, cipherB64);
            ps.setLong(6, System.currentTimeMillis());
            ps.setInt(7, delivered ? 1 : 0);
            ps.executeUpdate();
            try (ResultSet rk = ps.getGeneratedKeys()) {
                if (rk.next()) return rk.getInt(1);
                return -1;
            }
        }
    }

    public static class MessageRow {
        public final int id;
        public final String recipient, sender, encKeyB64, ivB64, cipherB64;
        public final long ts;
        public MessageRow(int id, String recipient, String sender, String encKeyB64, String ivB64, String cipherB64, long ts) {
            this.id = id;
            this.recipient = recipient;
            this.sender = sender;
            this.encKeyB64 = encKeyB64;
            this.ivB64 = ivB64;
            this.cipherB64 = cipherB64;
            this.ts = ts;
        }
    }

    public static synchronized List<MessageRow> getUndeliveredMessages(String recipient) throws SQLException {
        String sql = "SELECT id, sender, encKeyB64, ivB64, cipherB64, timestamp FROM messages WHERE recipient = ? AND delivered = 0 ORDER BY id ASC";
        List<MessageRow> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, recipient);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(new MessageRow(
                            rs.getInt("id"),
                            recipient,
                            rs.getString("sender"),
                            rs.getString("encKeyB64"),
                            rs.getString("ivB64"),
                            rs.getString("cipherB64"),
                            rs.getLong("timestamp")
                    ));
                }
            }
        }
        return out;
    }

    public static synchronized void markDelivered(int id) throws SQLException {
        String sql = "UPDATE messages SET delivered = 1 WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, id);
            ps.executeUpdate();
        }
    }
}
