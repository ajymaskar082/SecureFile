
package kz.securefile;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class DecryptionService {

    private static final byte[] MAGIC =
            {'S', 'F', 'I', 'L', 'E', '0', '0', '1'};

    private static final int VERSION = 1;
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;
    private static final int BUFFER_SIZE = 64 * 1024;

    private DecryptionService() {
    }

    public static void decrypt(
            Path input,
            Path output,
            char[] password
    ) throws IOException, GeneralSecurityException {

        validatePaths(input, output);

        if (password == null || password.length < 8) {
            throw new IllegalArgumentException(
                    "Құпиясөз кемінде 8 таңбадан тұруы керек."
            );
        }

        Path temporary = Files.createTempFile(
                output.toAbsolutePath().getParent(),
                "securefile-decrypt-",
                ".tmp"
        );

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];

        try {
            try (DataInputStream in = new DataInputStream(
                    new BufferedInputStream(
                            Files.newInputStream(input)));
                 OutputStream out = new BufferedOutputStream(
                         Files.newOutputStream(temporary))) {

                byte[] magic = new byte[MAGIC.length];
                in.readFully(magic);

                if (!Arrays.equals(magic, MAGIC)) {
                    throw new IOException(
                            "Файл форматы SecureFile форматына сәйкес емес."
                    );
                }

                int version = in.readUnsignedByte();

                if (version != VERSION) {
                    throw new IOException(
                            "Файл нұсқасына қолдау көрсетілмейді."
                    );
                }

                in.readFully(salt);
                in.readFully(iv);

                SecretKey key =
                        KeyDerivation.deriveKey(password, salt);

                Cipher cipher = Cipher.getInstance(
                        "AES/GCM/NoPadding"
                );

                cipher.init(
                        Cipher.DECRYPT_MODE,
                        key,
                        new GCMParameterSpec(TAG_LENGTH, iv)
                );

                byte[] buffer = new byte[BUFFER_SIZE];
                int read;

                while ((read = in.read(buffer)) != -1) {

                    byte[] decrypted = cipher.update(
                            buffer, 0, read
                    );

                    if (decrypted != null) {
                        out.write(decrypted);
                    }
                }

                // GCM аутентификациясы осы жерде тексеріледі.
                // Қате болса, файл соңғы орынға көшірілмейді.
                byte[] finalData = cipher.doFinal();
                out.write(finalData);
            }

            moveIntoPlace(temporary, output);

        } catch (AEADBadTagException ex) {
            throw new GeneralSecurityException(
                    "Құпиясөз қате немесе файл өзгертілген.",
                    ex
            );

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
            throw new IOException(
                    "Шифрланған файл табылмады."
            );
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
        } catch (
                java.nio.file.AtomicMoveNotSupportedException ex
        ) {
            Files.move(temporary, output);
        }
    }
}
