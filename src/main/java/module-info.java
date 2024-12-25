module com.example.cryptoapp {
    requires javafx.controls;
    requires javafx.fxml;
    //requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires bcprov.ext.jdk15to18;


    opens com.example.cryptoapp to javafx.fxml;
    exports com.example.cryptoapp;
}