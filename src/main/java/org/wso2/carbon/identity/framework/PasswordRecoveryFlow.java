package org.wso2.carbon.identity.framework;

import java.net.http.*;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.*;
import com.fasterxml.jackson.databind.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class PasswordRecoveryFlow {

    private static final HttpClient client;

    static {
        try {
            client = createInsecureClient();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final String BASE_URL = "https://localhost:9443/api/users/v2/recovery/password";
    private static String flowConfirmationCode;
    private static String recoveryCode;
    private static String resetCode;
    private static String lastResetCode;

    // ANSI color codes for logging
    private static final String RESET = "\033[0m";
    private static final String RED = "\033[31m";      // Error logs
    private static final String GREEN = "\033[32m";    // Success logs
    private static final String YELLOW = "\033[33m";   // Warning logs
    private static final String BLUE = "\033[34m";     // Info logs

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Step 1: Enter username
        System.out.println("Enter username: ");
        String username = scanner.nextLine();

        List<Node> nodes = initializeNodes();

        // Step 3: Loop through nodes and call recover API
        for (Node node : nodes) {
            processNode(scanner, node, username);  // Pass username to processNode method
        }

        // Step 5: Ask for new password
        logInfo("Enter new password: ");
        String newPassword = scanner.nextLine();

        resetPassword(newPassword);
    }

    private static List<Node> initializeNodes() {
        List<Node> nodes = new ArrayList<>();

        nodes.add(new Node(2, "SMS", null));
        nodes.add(new Node(1, "Email", null));

        return nodes;
    }

    private static void processNode(Scanner scanner, Node node, String username) throws Exception {
        String nodeId = String.valueOf(node.getId());
        String nodeName = node.getName();

        // Step 2: Call init API and get necessary info
        logInfo("Calling init API for node \"" + nodeName + "\"...");
        HttpResponse<String> initResponse = sendPostRequest(BASE_URL + "/init", createInitRequestBody(username));  // Pass username to the request body
        JsonNode initJson = mapper.readTree(initResponse.body()).get(0);
        flowConfirmationCode = initJson.get("flowConfirmationCode").asText();
        recoveryCode = initJson.get("channelInfo").get("recoveryCode").asText();

        // Step 3: Call recover API
        logInfo("Calling recover API for node \"" + nodeName + "\"...");
        sendPostRequest(BASE_URL + "/recover", createRecoverRequestBody(nodeId));

        // Step 4: Prompt for OTP and confirm
        System.out.println("Enter OTP for node \"" + nodeName + "\": ");
        String otp = scanner.nextLine();
        confirmOtp(nodeName, otp);
    }

    private static HttpResponse<String> sendPostRequest(String url, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Basic YWRtaW46YWRtaW4=")
                .header("Content-Type", "application/json")
                .header("accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String createInitRequestBody(String username) {
        return "{\n" +
                "  \"claims\": [\n" +
                "    {\n" +
                "      \"uri\": \"http://wso2.org/claims/username\",\n" +
                "      \"value\": \"" + username + "\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }

    private static String createRecoverRequestBody(String nodeId) {
        return String.format("{\"recoveryCode\":\"%s\",\"channelId\":\"%s\"}", recoveryCode, nodeId);
    }

    private static void confirmOtp(String nodeName, String otp) throws Exception {
        HttpRequest confirmRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/confirm"))
                .header("Authorization", "Basic YWRtaW46YWRtaW4=")
                .header("Content-Type", "application/json")
                .header("accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        String.format("{\"confirmationCode\":\"%s\",\"otp\":\"%s\"}", flowConfirmationCode, otp)))
                .build();

        HttpResponse<String> confirmResponse = client.send(confirmRequest, HttpResponse.BodyHandlers.ofString());
        JsonNode confirmJson = mapper.readTree(confirmResponse.body());

        if (confirmResponse.statusCode() == 200 && confirmJson.has("resetCode")) {
            resetCode = confirmJson.get("resetCode").asText();
            lastResetCode = resetCode;
            logSuccess("Authenticator \"" + nodeName + "\" confirmed successfully.");
        }
    }

    private static void resetPassword(String newPassword) throws Exception {
        HttpRequest resetRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/reset"))
                .header("Authorization", "Basic YWRtaW46YWRtaW4=")
                .header("Content-Type", "application/json")
                .header("accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        String.format("{\"resetCode\":\"%s\",\"flowConfirmationCode\":\"%s\",\"password\":\"%s\"}",
                                lastResetCode, flowConfirmationCode, newPassword)))
                .build();

        HttpResponse<String> resetResponse = client.send(resetRequest, HttpResponse.BodyHandlers.ofString());
        JsonNode resetJson = mapper.readTree(resetResponse.body());

        if (resetJson.has("code") && "PWR-02005".equals(resetJson.get("code").asText())) {
            logSuccess("Password reset successful.");
        } else {
            logError("Password reset failed: " + resetResponse.body());
        }
    }

    private static HttpClient createInsecureClient() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .build();
    }

    // Logging functions with color
    private static void logInfo(String message) {
        System.out.println(YELLOW + "[INFO] " + message + RESET);
    }

    private static void logSuccess(String message) {
        System.out.println(BLUE + "[SUCCESS] " + message + RESET);
    }

    private static void logError(String message) {
        System.out.println(RED + "[ERROR] " + message + RESET);
    }
}
