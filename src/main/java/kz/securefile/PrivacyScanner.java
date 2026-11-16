
package kz.securefile;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PrivacyScanner {

    private static final Pattern IIN_PATTERN =
            Pattern.compile("(?<!\\d)\\d{12}(?!\\d)");

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile(
                    "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
            );

    private static final Pattern PHONE_PATTERN =
            Pattern.compile(
                    "(?<!\\d)(?:\\+7|8)[\\s()-]*\\d{3}[\\s()-]*\\d{3}[\\s-]*\\d{2}[\\s-]*\\d{2}(?!\\d)"
            );

    public static ScanResult scan(File file) throws IOException {

        if (file == null || !file.isFile()) {
            throw new IOException("Файл табылмады.");
        }

        String name = file.getName().toLowerCase();

        if (!name.endsWith(".txt") && !name.endsWith(".csv")) {
            throw new IOException(
                    "Тек TXT және CSV файлдары қолдау көрсетіледі."
            );
        }

        int iinCount = 0;
        int phoneCount = 0;
        int emailCount = 0;

        try (BufferedReader reader = Files.newBufferedReader(
                file.toPath(), StandardCharsets.UTF_8)) {

            String line;

            while ((line = reader.readLine()) != null) {

                iinCount += countMatches(IIN_PATTERN, line);
                phoneCount += countMatches(PHONE_PATTERN, line);
                emailCount += countMatches(EMAIL_PATTERN, line);
            }
        }

        return new ScanResult(iinCount, phoneCount, emailCount);
    }

    private static int countMatches(Pattern pattern, String text) {

        Matcher matcher = pattern.matcher(text);
        int count = 0;

        while (matcher.find()) {
            count++;
        }

        return count;
    }

    public record ScanResult(
            int iinCount,
            int phoneCount,
            int emailCount
    ) {

        public int getTotalCount() {
            return iinCount + phoneCount + emailCount;
        }

        public String getRiskLevel() {

            int total = getTotalCount();

            if (total == 0) {
                return "Төмен";
            }

            if (total <= 2) {
                return "Орташа";
            }

            return "Жоғары";
        }

        public String getReport() {

            return """
                    ===== PRIVACY RADAR =====

                    ЖСН форматына ұқсас деректер: %d
                    Телефон нөмірлері: %d
                    Email мекенжайлары: %d

                    Барлығы табылған: %d
                    Қауіп деңгейі: %s

                    Ескерту: Нәтижелер үлгі бойынша анықталды.
                    """.formatted(
                    iinCount,
                    phoneCount,
                    emailCount,
                    getTotalCount(),
                    getRiskLevel()
            );
        }
    }
}
