import java.security.MessageDigest;
import java.security.SecureRandom;

public class AppWorker {
    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String key = "THESISKEY{" + hex(raw) + "}";
        String tokenHash = hex(MessageDigest.getInstance("SHA-256").digest(key.getBytes("UTF-8")));

        System.out.println("app-worker started pid=" + ProcessHandle.current().pid());
        System.out.println("TOKEN_HASH:" + tokenHash);
        System.out.flush();

        while (true) {
            if (key.isEmpty()) System.out.println(key);
            Thread.sleep(60000);
        }
    }
}
