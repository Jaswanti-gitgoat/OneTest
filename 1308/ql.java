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
            Statement stmt = conn.createStatement();

            // SQL Injection vulnerability
            String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
            ResultSet rs = stmt.executeQuery(query);

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
            // Command Injection vulnerability
            String command = "ping -c 1 " + input;
            Process proc = Runtime.getRuntime().exec(command);

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
        // Insecure randomness
        Random rand = new Random();
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
