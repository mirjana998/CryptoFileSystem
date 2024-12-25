package com.example.cryptoapp;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;


import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class SignUpController {

    @FXML
    private TextField usernameTextField;

    @FXML
    private PasswordField passwordField;

    @FXML
    private Button saveButton;

    @FXML
    private Button signInButton;

    @FXML
    private Button btnClose;

    @FXML
    private Label textLabel;

    private static final String provider = "BC";

    private static final String algorithm = "SHA256withRSA";

    public static final String userPath =  System.getProperty("user.dir") + File.separator + "root" + File.separator + "cert" + File.separator + "users.txt";

    private static final String caCertPath = System.getProperty("user.dir") + File.separator + "root" + File.separator + "cert" + File.separator + "ca" + File.separator + "ca-cert.der";
    private static final String caKeyPath = System.getProperty("user.dir") + File.separator + "root" + File.separator + "cert" + File.separator + "ca" + File.separator + "ca-key.der";

    private static final String serialFile = System.getProperty("user.dir") + File.separator +
            "root" + File.separator + "cert" + File.separator + "serial.txt";
    @FXML
    void saveButtonClicked(ActionEvent event) throws Exception{
        if (passwordField.getText().isEmpty() || usernameTextField.getText().isEmpty()) {
            textLabel.setText("Please enter text in all textfields.");
        }
        else if(usernameTextField.getText().contains(".") || usernameTextField.getText().contains("$")) {
            textLabel.setText("Username should not contain symbols such as $, #, !, %, etc.");
        }
        else {
            boolean check = true;
            File userFile = new File(userPath);
            Scanner userFileRead = new Scanner(userFile);
            while (userFileRead.hasNextLine()) {
                String userLine = userFileRead.nextLine();
                String[] array = userLine.split("%");
                if (array[0].equals(usernameTextField.getText())) {
                        textLabel.setText("Please enter another username.");
                        check = false;
                }
            }
            userFileRead.close();
            if(check) {
                    FileWriter userFileWrite = new FileWriter(userPath,true);
                    BufferedWriter bufferedWriter = new BufferedWriter(userFileWrite);
                    bufferedWriter.newLine();
                    bufferedWriter.append(usernameTextField.getText() + "%" + "\n");
                    bufferedWriter.close();

                    createCertificate(usernameTextField.getText(), passwordField.getText());

                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hash = digest.digest(passwordField.getText().getBytes(StandardCharsets.UTF_8));
                    String hashPassword = String.format("%064x", new BigInteger(1, hash));

                    String usernameAndPassword = usernameTextField.getText() + "%" + hashPassword + "%";

                    List<String> fileContent = new ArrayList<>(Files.readAllLines(Path.of(userPath), StandardCharsets.UTF_8));

                    for (int i = 0; i < fileContent.size(); i++) {
                        if (fileContent.get(i).equals(usernameTextField.getText()+"%")) {
                        fileContent.set(i, usernameAndPassword);
                        break;
                        }
                    }

                    Files.write(Path.of(userPath), fileContent, StandardCharsets.UTF_8);

                    textLabel.setText("Account successfully created.");
                    signInButton.setDisable(false);

            }
        }
    }


    @FXML
    void signInButtonClicked(ActionEvent event) throws Exception{
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("signInDS.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 795, 350);
        Stage stage = new Stage();
        stage.setScene(scene);
        stage.show();

    }

    @FXML
    void btnCloseClicked(ActionEvent event) {
        Stage stage = (Stage) btnClose.getScene().getWindow();
        stage.close();
    }

    public static KeyPair generateKeypair() throws GeneralSecurityException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();

    }

    public static void createCertificate(String username, String password) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        File caFile = new File(caCertPath);
        FileInputStream fis = new FileInputStream(caFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);
        File caKeyDer = new File(caKeyPath);
        KeyPair caKeyPair = new KeyPair(caCert.getPublicKey(),readPrivateKey(caKeyDer));
        X500Name caName = new X500Name(caCert.getSubjectX500Principal().getName());

        //setting up begin and end date of future end-entity certificate
        Date beginDate = Calendar.getInstance().getTime();
        Calendar c = Calendar.getInstance();
        c.setTime(beginDate);
        c.add(Calendar.MONTH, 6);
        Date endDate = c.getTime();

        //creating public and private key
        KeyPair endEntityKeyPair = generateKeypair();
        PrivateKey privateKey = endEntityKeyPair.getPrivate();
        byte[] buffer = privateKey.getEncoded();
        File keyFile = new File(System.getProperty("user.dir") + File.separator +
                "userKeys" + File.separator + username + ".der");
        Files.write(keyFile.toPath(),buffer);

        //serial number
        BigInteger serial;
        BufferedReader serialReader = new BufferedReader(new FileReader(serialFile));
        String lineSerial = serialReader.readLine();
        serialReader.close();
        serial = new BigInteger(lineSerial);
        BigInteger serial1 = serial.add(BigInteger.valueOf(1));
        FileWriter serialWriter = new FileWriter(serialFile);
        serialWriter.write(serial1.toString());
        serialWriter.close();

        //end-entitiy CN
        X500Name endEntityName = new X500Name("CN=" + username);

        X509v3CertificateBuilder endEntityCertBuilder = new JcaX509v3CertificateBuilder(caName, serial, beginDate, endDate,endEntityName,endEntityKeyPair.getPublic());


        ContentSigner signerCA = new JcaContentSignerBuilder(algorithm).setProvider(provider).build(caKeyPair.getPrivate());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        endEntityCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(endEntityKeyPair.getPublic()))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature));



        X509CertificateHolder endEntityCertHolder = endEntityCertBuilder.build(signerCA);
        CertificateFactory endEntityCertFactory = CertificateFactory.getInstance("X.509");
        X509Certificate endEntityCertificate = (X509Certificate) endEntityCertFactory.generateCertificate(new ByteArrayInputStream(endEntityCertHolder.getEncoded()));
        endEntityCertificate.verify(caKeyPair.getPublic(), provider);
        generateEndEntityKeystore(endEntityCertificate, username, password, endEntityKeyPair);

    }

    public static PrivateKey readPrivateKey(File caKeyDer) throws Exception {
        byte[] privKeyByteArray =Files.readAllBytes(caKeyDer.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        return keyFactory.generatePrivate(keySpec);
    }

    public static void generateEndEntityKeystore(X509Certificate cert, String username, String password, KeyPair keyPair) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", provider);
        ks.load(null,null);
        ks.setKeyEntry(username, keyPair.getPrivate(),null, new X509Certificate[]{cert});
        FileOutputStream keystoreOutputStream = new FileOutputStream(System.getProperty("user.dir") + File.separator +
                "root" + File.separator +"cert" + File.separator + "certs" + File.separator + username + ".pkx");
        ks.store(keystoreOutputStream,password.toCharArray());
        getEndEntityCertificateFromKeyStore(username, password);

    }

    public static void getEndEntityCertificateFromKeyStore(String username, String password) throws IOException{
        String inputFile = System.getProperty("user.dir") + File.separator +
                "root" + File.separator +"cert" + File.separator + "certs" + File.separator + username + ".pkx";
        String outputFile = System.getProperty("user.dir") + File.separator + "userCerts" + File.separator + username + ".crt";

        String[] command = {"openssl", "pkcs12", "-in", inputFile, "-nokeys", "-clcerts", "-out", outputFile, "-passin", "pass:" + password};
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        Process process = processBuilder.start();

    }




}
