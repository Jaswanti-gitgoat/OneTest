import java.io.*;
import java.sql.*;
import java.util.Random;

public class VulnerableExample {

    // Hardcoded credentials
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "password123";

    public static void main(String[] args) {
        String userInput = args.length > 0 ? args[0] : "default";

        sqlInjectionExample(userInput);
        commandInjectionExample(userInput);
        insecureRandomExample();
        pathTraversalExample(userInput);
    }

    public static void sqlInjectionExample(String userInput) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", DB_USER, DB_PASS);
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
            // Agentic Rule (ARNIE_INPUT_PREPARED_STATEMENTS): Use parameterized queries to separate data from code and prevent SQL injection | Agent: Arnica
            stmt.setString(1, userInput);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                System.out.println("User found: " + rs.getString("username"));
            }

            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void commandInjectionExample(String input) {
        try {
            // Agentic Rule (ARNIE_RCE_COMMAND_EXECUTION): Use ProcessBuilder with argument array to avoid shell interpretation and command injection | Agent: Arnica
            // Agentic Rule (ARNIE_RCE_ARGUMENT_SANITIZATION): Validate the hostname to allow only safe characters and reasonable length | Agent: Arnica
            String target = input == null ? "" : input.trim();
            if (!target.matches("^[a-zA-Z0-9._-]{1,253}$")) {
                throw new IOException("Invalid host parameter");
            }
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", target);
            pb.redirectErrorStream(true);
            Process proc = pb.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void insecureRandomExample() {
        // Agentic Rule (ARNIE_CRYPTO_RANDOM_GENERATION): Replace java.util.Random with SecureRandom for cryptographically secure token generation | Agent: Arnica
        java.security.SecureRandom rand = new java.security.SecureRandom();
        int token = rand.nextInt();
        System.out.println("Generated token: " + token);
    }

    public static void pathTraversalExample(String filename) {
        try {
            // Path traversal vulnerability
            File file = new File("/var/data/" + filename);
            BufferedReader reader = new BufferedReader(new FileReader(file));

            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Line: " + line);
            }
            reader.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
