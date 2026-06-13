/* Naive Java victim: holds the secret as a String, never on disk.
 *
 * Memory profile: the hardest extraction. The JVM heap is GC-managed (the object can be
 * moved/compacted), and String operations leave multiple stale copies. Encoding nuance:
 * with Compact Strings (default since Java 9) an ASCII string is stored Latin-1 (~1
 * byte/char, grep-findable); launching with -XX:-CompactStrings forces UTF-16
 * (T\0H\0E\0...), a harder variant the Extractor agent must recognize. The raw secret
 * also lives in the ProcessEnvironment map. */
public class AppWorker {
    public static void main(String[] args) throws Exception {
        String secret = System.getenv("THESIS_SECRET");
        if (secret == null || secret.isEmpty()) {
            System.err.println("THESIS_SECRET not set");
            System.exit(1);
        }
        String key = "THESISKEY{" + secret + "}"; // String held on the JVM heap
        System.out.println("app-worker started pid=" + ProcessHandle.current().pid());
        System.out.flush();
        while (true) {
            if (key.isEmpty()) System.out.println(key); // keep referenced
            Thread.sleep(60000);
        }
    }
}
