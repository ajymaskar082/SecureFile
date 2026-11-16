
package kz.securefile;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class EncryptionService {

    private static final byte[] MAGIC =
            {'S', 'F', 'I', 'L', 'E', '0', '0', '1'};

    private static final int VERSION = 1;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;
    private static final int BUFFER_SIZE = 64 * 1024;

    private EncryptionService() {
    }

    public static void encrypt(
            Path input,
            Path output,
            char[] password
    ) throws IOException, GeneralSecurityException {

        validatePaths(input, output);
        validatePassword(password);

        byte[] salt = KeyDerivation.generateSalt();
        byte[] iv = new byte[IV_LENGTH];

        new java.security.SecureRandom().nextBytes(iv);

        Path temporary = createTemporaryFile(output);

        try {
            SecretKey key =
                    KeyDerivation.deriveKey(password, salt);

            Cipher cipher = Cipher.getInstance(
                    "AES/GCM/NoPadding"
            );

            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    key,
                    new GCMParameterSpec(TAG_LENGTH, iv)
            );

            try (InputStream in = new BufferedInputStream(
                        Files.newInputStream(input));
                 OutputStream out = new BufferedOutputStream(
                        Files.newOutputStream(temporary))) {

                out.write(MAGIC);
                out.write(VERSION);
                out.write(salt);
                out.write(iv);

                byte[] buffer = new byte[BUFFER_SIZE];
                int read;

                while ((read = in.read(buffer)) != -1) {
                    byte[] encrypted = cipher.update(
                            buffer, 0, read
                    );

                    if (encrypted != null) {
                        out.write(encrypted);
                    }
                }

                byte[] finalData = cipher.doFinal();
                out.write(finalData);
            }

            moveIntoPlace(temporary, output);

        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Files.deleteIfExists(temporary);
        }
    }

    private static void validatePaths(
            Path input,
            Path output
    ) throws IOException {

        if (input == null || output == null
                || !Files.isRegularFile(input)) {
            throw new IOException("Бастапқы файл табылмады.");
        }

        Path source = input.toAbsolutePath().normalize();
        Path target = output.toAbsolutePath().normalize();

        if (source.equals(target)) {
            throw new IOException(
                    "Кіріс және шығыс файлдары бірдей болмауы керек."
            );
        }

        if (target.getParent() == null
                || !Files.isDirectory(target.getParent())) {
            throw new IOException(
                    "Шығыс бумасы табылмады."
            );
        }
    }

    private static void validatePassword(char[] password) {

        if (password == null || password.length < 8) {
            throw new IllegalArgumentException(
                    "Құпиясөз кемінде 8 таңбадан тұруы керек."
            );
        }
    }

    private static Path createTemporaryFile(
            Path output
    ) throws IOException {

        return Files.createTempFile(
                output.toAbsolutePath().getParent(),
                "securefile-",
                ".tmp"
        );
    }

    private static void moveIntoPlace(
            Path temporary,
            Path output
    ) throws IOException {

        try {
            Files.move(
                    temporary,
                    output,
                    StandardCopyOption.ATOMIC_MOVE
            );
        } catch (java.nio.file.AtomicMoveNotSupportedException ex) {
            Files.move(temporary, output);
        }
    }
}
