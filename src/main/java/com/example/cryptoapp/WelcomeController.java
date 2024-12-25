package com.example.cryptoapp;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.event.ActionEvent;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

public class WelcomeController {

    @FXML
    private Button signInButton;

    @FXML
    private Button signUpButton;

    @FXML
    private Button btnClose;

    @FXML
    void signInButtonOnAction(ActionEvent event) {
        try {
            FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("signInDS.fxml"));
            Scene scene = new Scene(fxmlLoader.load(), 795, 390);
            Stage stage = new Stage();
            stage.initStyle(StageStyle.UNDECORATED);
            stage.setScene(scene);
            stage.show();
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    @FXML
    void signUpButtonOnAction(ActionEvent event) {
        try {
            FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("signUp.fxml"));
            Scene scene = new Scene(fxmlLoader.load(), 400, 400);
            Stage stage = new Stage();
            stage.initStyle(StageStyle.UNDECORATED);
            stage.setScene(scene);
            stage.show();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    @FXML
    void btnCloseClicked(ActionEvent event) {
        Stage stage = (Stage) btnClose.getScene().getWindow();
        stage.close();
    }

}
