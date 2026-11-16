
package kz.securefile;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

public class MainApp extends Application {

    private File selectedFile;
    private Label fileLabel;
    private Label statusLabel;
    private TextArea resultArea;
    private PasswordField passwordField;

    @Override
    public void start(Stage stage) {

        Label title = new Label("SECUREFILE");
        title.setStyle(
                "-fx-font-size: 28px;" +
                "-fx-font-weight: bold;" +
                "-fx-text-fill: #2563eb;"
        );

        Label subtitle = new Label(
                "Файлдарыңызды тексеріңіз және қауіпсіз қорғаңыз"
        );

        Button selectButton = new Button("Файл таңдау");
        Button scanButton = new Button("Privacy Radar");
        Button encryptButton = new Button("Шифрлау");
        Button decryptButton = new Button("Дешифрлау");

        fileLabel = new Label("Әзірге файл таңдалмады");

        passwordField = new PasswordField();
        passwordField.setPromptText("Құпиясөз (кемінде 8 таңба)");

        resultArea = new TextArea();
        resultArea.setPromptText("Нәтижелер...");
        resultArea.setEditable(false);
        resultArea.setPrefRowCount(9);

        statusLabel = new Label("Жүйе дайын.");

        selectButton.setOnAction(e -> selectFile(stage));
        scanButton.setOnAction(e -> scanSelectedFile());
        encryptButton.setOnAction(e -> encryptFile(stage));
        decryptButton.setOnAction(e -> decryptFile(stage));

        VBox content = new VBox(20,
                title,
                subtitle,
                new Separator(),
                new Label("1. Файлды таңдаңыз"),
                selectButton,
                fileLabel,
                new Label("2. Құпиясөз"),
                passwordField,
                new HBox(10, scanButton, encryptButton, decryptButton),
                new Label("3. Нәтиже"),
                resultArea,
                statusLabel
        );

        content.setPadding(new Insets(30));
        content.setStyle("-fx-background-color: #f8fafc;");

        Scene scene = new Scene(content, 760, 620);

        stage.setTitle("SecureFile");
        stage.setMinWidth(680);
        stage.setMinHeight(550);
        stage.setScene(scene);
        stage.show();
    }

    private void selectFile(Stage stage) {

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Файл таңдаңыз");

        selectedFile = chooser.showOpenDialog(stage);

        if (selectedFile != null) {
            fileLabel.setText(selectedFile.getName());
            statusLabel.setText("Файл таңдалды.");
            resultArea.clear();
        }
    }

    private void scanSelectedFile() {

        if (selectedFile == null) {
            showMessage("Алдымен файл таңдаңыз.");
            return;
        }

        try {
            PrivacyScanner.ScanResult result =
                    PrivacyScanner.scan(selectedFile);

            resultArea.setText(result.getReport());
            statusLabel.setText("Тексеру аяқталды.");

        } catch (IOException ex) {
            showError(ex.getMessage());
        }
    }

    private void encryptFile(Stage stage) {

        if (selectedFile == null) {
            showMessage("Алдымен файл таңдаңыз.");
            return;
        }

        char[] password = passwordField.getText().toCharArray();

        try {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Шифрланған файлды сақтау");
            chooser.setInitialFileName(
                    selectedFile.getName() + ".enc"
            );

            File destination = chooser.showSaveDialog(stage);

            if (destination == null) return;

            EncryptionService.encrypt(
                    selectedFile.toPath(),
                    destination.toPath(),
                    password
            );

            resultArea.setText(
                    "Файл сәтті шифрланды!\n\n" +
                    "Алгоритм: AES-256-GCM\n" +
                    "Кілт алу: PBKDF2WithHmacSHA256\n" +
                    "Нәтиже: " + destination.getName()
            );

            statusLabel.setText("Шифрлау аяқталды.");

        } catch (IOException | GeneralSecurityException |
                 IllegalArgumentException ex) {
            showError(ex.getMessage());

        } finally {
            java.util.Arrays.fill(password, '\0');
            passwordField.clear();
        }
    }

    private void decryptFile(Stage stage) {

        if (selectedFile == null) {
            showMessage("Шифрланған файлды таңдаңыз.");
            return;
        }

        char[] password = passwordField.getText().toCharArray();

        try {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Қалпына келтірілген файлды сақтау");
            chooser.setInitialFileName("decrypted-file");

            File destination = chooser.showSaveDialog(stage);

            if (destination == null) return;

            DecryptionService.decrypt(
                    selectedFile.toPath(),
                    destination.toPath(),
                    password
            );

            resultArea.setText(
                    "Файл сәтті қалпына келтірілді!\n\n" +
                    "Аутентификация: сәтті\n" +
                    "Нәтиже: " + destination.getName()
            );

            statusLabel.setText("Дешифрлау аяқталды.");

        } catch (IOException | GeneralSecurityException |
                 IllegalArgumentException ex) {
            showError(ex.getMessage());

        } finally {
            java.util.Arrays.fill(password, '\0');
            passwordField.clear();
        }
    }

    private void showMessage(String message) {

        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("SecureFile");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showError(String message) {

        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Қате");
        alert.setHeaderText("Операция орындалмады");
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
