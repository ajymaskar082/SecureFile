
package kz.securefile;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;

public class KeyDerivation {

    private static final int SALT_LENGTH = 16;
    private static final int ITERATIONS = 600_000;
    private static final int KEY_LENGTH = 256;

    private static final SecureRandom RANDOM =
            new SecureRandom();

    private KeyDerivation() {
    }

    public static byte[] generateSalt() {

        byte[] salt = new byte[SALT_LENGTH];

        RANDOM.nextBytes(salt);

        return salt;
    }

    public static SecretKey deriveKey(
            char[] password,
            byte[] salt
    ) throws GeneralSecurityException {

        if (password == null || password.length == 0) {
            throw new IllegalArgumentException(
                    "Құпиясөз бос болмауы керек."
            );
        }

        if (salt == null || salt.length != SALT_LENGTH) {
            throw new IllegalArgumentException(
                    "Salt ұзындығы 16 байт болуы керек."
            );
        }

        PBEKeySpec spec = new PBEKeySpec(
                password,
                salt,
                ITERATIONS,
                KEY_LENGTH
        );

        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(
                            "PBKDF2WithHmacSHA256"
                    );

            byte[] keyBytes = factory
                    .generateSecret(spec)
                    .getEncoded();

            return new SecretKeySpec(
                    keyBytes,
                    "AES"
            );

        } finally {
            spec.clearPassword();
        }
    }

    public static int getIterations() {
        return ITERATIONS;
    }
}
