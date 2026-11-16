
package kz.securefile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SecureFileTest {

    @TempDir
    Path tempDir;

    private static final char[] PASSWORD =
            "SecurePassword2026".toCharArray();

    // 1. Salt ұзындығы 16 байт болуы керек.
    @Test
    void testSaltLength() {
        byte[] salt = KeyDerivation.generateSalt();

        assertEquals(16, salt.length);
    }

    // 2. Әр генерацияда жаңа Salt жасалуы керек.
    @Test
    void testSaltRandomness() {
        byte[] salt1 = KeyDerivation.generateSalt();
        byte[] salt2 = KeyDerivation.generateSalt();

        assertFalse(Arrays.equals(salt1, salt2));
    }

    // 3. AES кілті 256 бит болуы керек.
    @Test
    void testKeyLength() throws Exception {
        byte[] salt = KeyDerivation.generateSalt();

        SecretKey key =
                KeyDerivation.deriveKey(PASSWORD, salt);

        assertEquals(32, key.getEncoded().length);
    }

    // 4. Бірдей құпиясөз және Salt бірдей кілт беруі керек.
    @Test
    void testSamePasswordProducesSameKey() throws Exception {
        byte[] salt = KeyDerivation.generateSalt();

        SecretKey key1 =
                KeyDerivation.deriveKey(PASSWORD, salt);

        SecretKey key2 =
                KeyDerivation.deriveKey(PASSWORD, salt);

        assertArrayEquals(
                key1.getEncoded(),
                key2.getEncoded()
        );
    }

    // 5. Әртүрлі Salt әртүрлі кілт беруі керек.
    @Test
    void testDifferentSaltProducesDifferentKey()
            throws Exception {

        byte[] salt1 = KeyDerivation.generateSalt();
        byte[] salt2 = KeyDerivation.generateSalt();

        SecretKey key1 =
                KeyDerivation.deriveKey(PASSWORD, salt1);

        SecretKey key2 =
                KeyDerivation.deriveKey(PASSWORD, salt2);

        assertFalse(Arrays.equals(
                key1.getEncoded(),
                key2.getEncoded()
        ));
    }

    // 6. Бос құпиясөз қабылданбауы керек.
    @Test
    void testEmptyPasswordRejected() {
        byte[] salt = KeyDerivation.generateSalt();

        assertThrows(
                IllegalArgumentException.class,
                () -> KeyDerivation.deriveKey(
                        new char[0], salt
                )
        );
    }

    // 7. Қате ұзындықтағы Salt қабылданбауы керек.
    @Test
    void testInvalidSaltRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyDerivation.deriveKey(
                        PASSWORD, new byte[8]
                )
        );
    }

    // 8. Шифрлау нәтижесінде SecureFile форматы жасалуы керек.
    @Test
    void testEncryptionCreatesValidFile() throws Exception {

        Path input = createInputFile("Hello SecureFile!");
        Path output = tempDir.resolve("encrypted.enc");

        EncryptionService.encrypt(
                input, output, PASSWORD
        );

        assertTrue(Files.exists(output));
        assertTrue(Files.size(output) > 37);

        byte[] header = Files.readAllBytes(output);

        assertEquals('S', header[0]);
        assertEquals('F', header[1]);
        assertEquals('I', header[2]);
        assertEquals('L', header[3]);
        assertEquals('E', header[4]);
        assertEquals(1, header[8]);
    }

    // 9. Шифрланған файл бастапқы қалпына келуі керек.
    @Test
    void testEncryptionDecryptionRoundTrip()
            throws Exception {

        byte[] original =
                "SecureFile encryption test data 2026"
                        .getBytes();

        Path input = tempDir.resolve("original.txt");
        Path encrypted = tempDir.resolve("file.enc");
        Path decrypted = tempDir.resolve("restored.txt");

        Files.write(input, original);

        EncryptionService.encrypt(
                input, encrypted, PASSWORD
        );

        DecryptionService.decrypt(
                encrypted, decrypted, PASSWORD
        );

        assertArrayEquals(
                original,
                Files.readAllBytes(decrypted)
        );
    }

    // 10. Қате құпиясөзбен файл ашылмауы керек.
    @Test
    void testWrongPasswordRejected() throws Exception {

        Path input = createInputFile("Secret document");
        Path encrypted = tempDir.resolve("secret.enc");
        Path decrypted = tempDir.resolve("wrong.txt");

        EncryptionService.encrypt(
                input, encrypted, PASSWORD
        );

        assertThrows(
                GeneralSecurityException.class,
                () -> DecryptionService.decrypt(
                        encrypted,
                        decrypted,
                        "WrongPassword2026".toCharArray()
                )
        );

        assertFalse(Files.exists(decrypted));
    }

    // 11. Өзгертілген файл қабылданбауы керек.
    @Test
    void testTamperedFileRejected() throws Exception {

        Path input = createInputFile(
                "Important confidential document"
        );

        Path encrypted = tempDir.resolve("tampered.enc");
        Path decrypted = tempDir.resolve("tampered.txt");

        EncryptionService.encrypt(
                input, encrypted, PASSWORD
        );

        byte[] data = Files.readAllBytes(encrypted);

        data[data.length - 1] ^= 1;

        Files.write(encrypted, data);

        assertThrows(
                GeneralSecurityException.class,
                () -> DecryptionService.decrypt(
                        encrypted, decrypted, PASSWORD
                )
        );

        assertFalse(Files.exists(decrypted));
    }

    // 12. Қате файл тақырыбы қабылданбауы керек.
    @Test
    void testInvalidFileFormatRejected() throws Exception {

        Path invalid = tempDir.resolve("invalid.enc");
        Path output = tempDir.resolve("invalid.txt");

        Files.write(
                invalid,
                "NOTASECUREFILE".getBytes()
        );

        assertThrows(
                IOException.class,
                () -> DecryptionService.decrypt(
                        invalid, output, PASSWORD
                )
        );

        assertFalse(Files.exists(output));
    }

    // 13. Қолдау көрсетілмейтін формат нұсқасы қабылданбауы керек.
    @Test
    void testUnsupportedVersionRejected() throws Exception {

        Path invalid = tempDir.resolve("version.enc");
        Path output = tempDir.resolve("version.txt");

        byte[] header = new byte[37];

        byte[] magic = {
                'S', 'F', 'I', 'L', 'E', '0', '0', '1'
        };

        System.arraycopy(
                magic, 0, header, 0, magic.length
        );

        header[8] = 2;

        Files.write(invalid, header);

        assertThrows(
                IOException.class,
                () -> DecryptionService.decrypt(
                        invalid, output, PASSWORD
                )
        );

        assertFalse(Files.exists(output));
    }

    // 14. Privacy Radar үш түрлі деректі анықтауы керек.
    @Test
    void testPrivacyScannerDetectsSensitiveData()
            throws Exception {

        Path file = tempDir.resolve("personal.csv");

        Files.writeString(
                file,
                "Name,IIN,Phone,Email\n" +
                "Test,123456789012,+7 701 123 45 67," +
                "test@example.com\n"
        );

        PrivacyScanner.ScanResult result =
                PrivacyScanner.scan(file.toFile());

        assertEquals(1, result.iinCount());
        assertEquals(1, result.phoneCount());
        assertEquals(1, result.emailCount());
        assertEquals(3, result.getTotalCount());
    }

    // 15. Қолдау көрсетілмейтін файл форматы қабылданбауы керек.
    @Test
    void testPrivacyScannerRejectsUnsupportedFormat()
            throws Exception {

        Path file = tempDir.resolve("document.pdf");

        Files.writeString(file, "Sample content");

        assertThrows(
                IOException.class,
                () -> PrivacyScanner.scan(file.toFile())
        );
    }

    private Path createInputFile(String content)
            throws IOException {

        Path file = tempDir.resolve("input.txt");

        Files.writeString(file, content);

        return file;
    }
}
