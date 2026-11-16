
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
        passwordField.setPromptText("Құпиясөз енгізіңіз");

        resultArea = new TextArea();
        resultArea.setPromptText(
                "Тексеру және шифрлау нәтижелері..."
        );
        resultArea.setEditable(false);
        resultArea.setPrefRowCount(8);

        statusLabel = new Label("Жүйе дайын.");
        statusLabel.setStyle("-fx-text-fill: #16a34a;");

        selectButton.setOnAction(e -> selectFile(stage));

        scanButton.setOnAction(e -> scanSelectedFile());

        encryptButton.setOnAction(e ->
                statusLabel.setText(
                        "Шифрлау модулі келесі кезеңде қосылады."
                )
        );

        decryptButton.setOnAction(e ->
                statusLabel.setText(
                        "Дешифрлау модулі келесі кезеңде қосылады."
                )
        );

        VBox fileSection = new VBox(10,
                new Label("1. Файлды таңдаңыз"),
                selectButton,
                fileLabel
        );

        VBox securitySection = new VBox(10,
                new Label("2. Құпиясөз"),
                passwordField
        );

        HBox actions = new HBox(10,
                scanButton,
                encryptButton,
                decryptButton
        );

        actions.setAlignment(Pos.CENTER_LEFT);

        VBox resultSection = new VBox(10,
                new Label("3. Privacy Radar нәтижесі"),
                resultArea,
                statusLabel
        );

        VBox content = new VBox(22,
                title,
                subtitle,
                new Separator(),
                fileSection,
                securitySection,
                actions,
                resultSection
        );

        content.setPadding(new Insets(30));
        content.setStyle("-fx-background-color: #f8fafc;");

        Scene scene = new Scene(content, 720, 580);

        stage.setTitle("SecureFile - File Security System");
        stage.setMinWidth(650);
        stage.setMinHeight(520);
        stage.setScene(scene);
        stage.show();
    }

    private void selectFile(Stage stage) {

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Қорғалатын файлды таңдаңыз");

        selectedFile = chooser.showOpenDialog(stage);

        if (selectedFile != null) {
            fileLabel.setText(selectedFile.getName());
            statusLabel.setText("Файл сәтті таңдалды.");
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

            statusLabel.setText(
                    "Тексеру аяқталды. Қауіп деңгейі: "
                            + result.getRiskLevel()
            );

        } catch (IOException ex) {

            resultArea.setText(
                    "Қате: " + ex.getMessage()
            );

            statusLabel.setText("Файлды тексеру мүмкін болмады.");
        }
    }

    private void showMessage(String message) {

        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("SecureFile");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
