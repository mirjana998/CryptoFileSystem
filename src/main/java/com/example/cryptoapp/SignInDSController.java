package com.example.cryptoapp;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class SignInDSController{

    @FXML
    private AnchorPane anchorPane;
    @FXML
    private Button btnInsert;
    @FXML
    private Button btnLogin;
    @FXML
    private Button btnClose;
    @FXML
    private Button btnNextCert;
    @FXML
    private Button btnNextUsr;
    @FXML
    private Button btnShow;
    @FXML
    private Button btnUpload;
    @FXML
    private Label lblMsgCert;
    @FXML
    private Label lblMsgVerify;
    @FXML
    private Label lblMsgUser;
    @FXML
    private Label lblMsgFile;
    @FXML
    private PasswordField txtPassword;
    @FXML
    private ListView<String> listView;
    @FXML
    private TextField txtUsername;

    private static final String provider = "BC";
    private static final String algorithm = "SHA256withRSA";
    public static int counter = 0;
    public String[] userFiles = {""};
    public static final String userPath =  System.getProperty("user.dir") + File.separator + "root" + File.separator + "cert" + File.separator + "users.txt";
    private static final String caCertPath = System.getProperty("user.dir") + File.separator + "root" + File.separator + "cert" + File.separator + "ca" + File.separator + "ca-cert.der";
    private static final String caKeyPath = System.getProperty("user.dir") + File.separator + "root" + File.separator + "cert" + File.separator + "ca" + File.separator + "ca-key.der";

    private static final String crListPath = System.getProperty("user.dir") + File.separator + "root" + File.separator + "cert" + File.separator + "crl" + File.separator + "CRList.crl";

    public static X509Certificate currentUserCert;
    public static KeyPair userKeyPair;
    public static String selectedFile = null;
    public boolean credentialsVerifiedOK = false;
    public X509CRL currentCRL;
    public X509CRL previousCRL;


    @FXML
    void btnInsertClicked(ActionEvent event) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        File file = null;
        currentCRL = getCurrentCRL();
        while (file == null) {
            lblMsgCert.setText("Please enter certificate.");
            FileChooser fileOpen = new FileChooser();
            fileOpen.setTitle("Open File Dialog");
            Stage stage = (Stage) anchorPane.getScene().getWindow();
            file = fileOpen.showOpenDialog(stage);
        }
        String fileName = file.getName();

        //if file is cert file
        if (fileName.contains(".crt")) {
            lblMsgCert.setText("You have chosen " + fileName);
            //create user cert
            FileInputStream userFis = new FileInputStream(file);
            CertificateFactory userCF = CertificateFactory.getInstance("X.509");
            currentUserCert = (X509Certificate) userCF.generateCertificate(userFis);
            userFis.close();

            //create ca cert
            File caFile = new File(caCertPath);
            FileInputStream fis = new FileInputStream(caFile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);
            fis.close();

            //if crl not empty, check if cert is revoked
            if (currentCRL.getRevokedCertificates() != null) {
                //if cert is revoked
                if (currentCRL.getRevokedCertificate(currentUserCert.getSerialNumber()) != null) {
                    lblMsgCert.setText("Certificate revoked.");
                    lblMsgVerify.setText("Verified NOT OK!");
                    btnNextCert.setDisable(true);
                }
                //cert not revoked
                else {
                    try {
                        currentUserCert.verify(caCert.getPublicKey(), "BC");
                        currentUserCert.checkValidity(Calendar.getInstance().getTime());
                        lblMsgVerify.setText("Verified OK!");
                        btnNextCert.setDisable(false);
                    } catch (Exception e) {
                        lblMsgVerify.setText("Verified NOT OK!");
                        btnNextCert.setDisable(true);
                    }

                }
            }
            //if crl empty
            else {
                try {
                    currentUserCert.verify(caCert.getPublicKey(), "BC");
                    currentUserCert.checkValidity(Calendar.getInstance().getTime());
                    lblMsgVerify.setText("Verified OK!");
                    btnNextCert.setDisable(false);
                } catch (Exception e) {
                    lblMsgVerify.setText("Verified NOT OK!");
                    btnNextCert.setDisable(true);
                }
            }
        }
        //if file is not cert file
        else{
                lblMsgCert.setText("Error! False format.");
                btnNextCert.setDisable(true);
                lblMsgVerify.setText("Verified NOT OK!");
            }
    }

    @FXML
    void btnNextCertClicked(ActionEvent event) {
        counter=0;
        txtUsername.setDisable(false);
        txtPassword.setDisable(false);
        btnLogin.setDisable(false);
    }

    @FXML
    void btnCloseClicked(ActionEvent event) {
        if(credentialsVerifiedOK) {
            File keyFile = new File(System.getProperty("user.dir") + File.separator +
                    "root" + File.separator + "cert" + File.separator + "key" + File.separator + txtUsername.getText() + ".der");
            //keyFile.setWritable(true);
            keyFile.delete();
        }
        Stage stage = (Stage) btnClose.getScene().getWindow();
        stage.close();
    }


    @FXML
    void btnLoginClicked(ActionEvent event) throws Exception {
        currentCRL = getCurrentCRL();

        //if username and password textfields are empty
        if (txtPassword.getText().isEmpty() || txtUsername.getText().isEmpty()) {
            lblMsgUser.setText("Please enter text in all textfields.");
            btnNextUsr.setDisable(true);
        }
        //not empty
        else {
                String certName = txtUsername.getText() + ".crt";
                //correct credentials
                if(lblMsgCert.getText().contains(certName) && checkPassword(txtPassword.getText(), txtUsername.getText())) {
                    if (counter < 3) {
                        credentialsVerifiedOK = true;
                        String privKey = System.getProperty("user.dir") + File.separator + "userKeys" + File.separator + txtUsername.getText() + ".der";
                        String userKey = System.getProperty("user.dir") + File.separator +
                                "root" + File.separator +"cert" + File.separator + "key" + txtUsername.getText() + ".der";
                        FileInputStream fis = new FileInputStream(privKey);
                        FileOutputStream fos = new FileOutputStream(userKey);
                        int i;
                        while ((i = fis.read()) != -1) {
                            fos.write(i);
                        }
                        fis.close();
                        fos.close();
                        File file = new File(userKey);
                        userKeyPair = new KeyPair(currentUserCert.getPublicKey(), readPrivateKey(file));
                        lblMsgUser.setText("You shall pass. Click Next.");
                        btnNextUsr.setDisable(false);
                    }
                    else if(counter == 3) {
                        lblMsgUser.setText("You have entered correct password. Your certificate is active again.");
                        btnNextUsr.setDisable(false);
                        refreshCRL(previousCRL);
                        counter = 0;
                    }
                    else {
                        lblMsgUser.setText("Your certificate is permanently revoked. Please sign up.");
                        btnNextUsr.setDisable(true);
                    }
                }
                //wrong credentials
                else {
                    if(counter < 2) {
                        lblMsgUser.setText("Please enter correct username and password.");
                        btnNextUsr.setDisable(true);
                        counter++;
                    }
                    else if(counter == 2)  {
                        lblMsgUser.setText("You've entered wrong credentials three times. Your certificate is revoked. Please enter correct password or make new account.");
                        previousCRL = getCurrentCRL();
                        updateCRList(currentUserCert);
                        currentCRL = getCurrentCRL();
                        counter++;
                        btnNextUsr.setDisable(true);
                    }
                    else {
                        lblMsgUser.setText("Your certificate is revoked, please sign up.");
                        btnNextUsr.setDisable(true);
                        counter++;
                    }
                }
        }
    }

    public static PrivateKey readPrivateKey(File keyDer) throws Exception {
        byte[] privKeyByteArray =Files.readAllBytes(keyDer.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        PrivateKey privKey = keyFactory.generatePrivate(keySpec);
        return privKey;
    }


    @FXML
    void btnNextUsrClicked(ActionEvent event) throws IOException {
        btnShow.setDisable(false);
        btnUpload.setDisable(false);

        List<String> fileContent = new ArrayList<>(Files.readAllLines(Path.of(userPath), StandardCharsets.UTF_8));
        for (int i = 0; i < fileContent.size(); i++) {
            if (fileContent.get(i).contains(txtUsername.getText())) {
                String[] array = fileContent.get(i).split("%");
                if(array.length > 2) {
                    for(int j=2, k=0; j < array.length ; j=j+2) {
                        userFiles[k] = array[j];
                        listView.getItems().addAll(userFiles);
                        listView.refresh();
                    }
                }
            }
        }
    }

    @FXML
    void btnUploadClicked(ActionEvent event) throws Exception {
        FileChooser fileOpen = new FileChooser();
        fileOpen.setTitle("Open File Dialog");
        Stage stage = (Stage) anchorPane.getScene().getWindow();
        File file = fileOpen.showOpenDialog(stage);
        if (file == null ){
            lblMsgFile.setText("Please choose file for upload.");
        }
        else {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(Files.readAllBytes(file.toPath()));
            String hashFile = String.format("%064x", new BigInteger(1, hash));
            hashFile = hashFile.concat("%");
            String fileNameOne = file.getName();
            String fileName = fileNameOne + "%" + hashFile;
            if (fileNameOne.contains("%")) {
                lblMsgFile.setText("File name contains character %, please rename file or choose another one.");
            } else {
                lblMsgFile.setText("");
                List<String> fileContent = new ArrayList<>(Files.readAllLines(Path.of(userPath), StandardCharsets.UTF_8));
                for (int i = 0; i < fileContent.size(); i++) {
                    if (fileContent.get(i).contains(txtUsername.getText())) {
                        if (fileContent.get(i).contains(fileName)) {
                            lblMsgFile.setText("File with such name already in file system.");
                            break;
                        } else {
                            splitFile(file);
                            listView.getItems().clear();
                            String line = fileContent.get(i).concat(fileName);
                            fileContent.set(i, line);
                            String[] array = fileContent.get(i).split("%");
                            for (int j = 2, k = 0; j < array.length; j = j + 2) {
                                userFiles[k] = array[j];
                                listView.getItems().addAll(userFiles);
                                listView.refresh();
                            }
                            lblMsgFile.setText("File successfully uploaded.");
                            break;
                        }
                    }
                }
                Files.write(Path.of(userPath), fileContent, StandardCharsets.UTF_8);
            }
        }
    }

    public void splitFile(File f) throws Exception {
        int fileSize =(int) f.length();
        int partsNumber = (int)Math.floor((Math.random()*(8-4+1)+4));
        String rootPath = System.getProperty("user.dir") + File.separator + "root" + File.separator +"dir";
        int partCounter = 1;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(txtUsername.getText().getBytes(StandardCharsets.UTF_8));
        String hashUsername = String.format("%064x", new BigInteger(1, hash));

        byte[] buffer = new byte[fileSize/partsNumber + 1];
        String fileName = f.getName();

        try(FileInputStream fis = new FileInputStream(f);
            BufferedInputStream bis = new BufferedInputStream(fis)) {
            int bytesAmount = 0;
            while ((bytesAmount = bis.read(buffer)) > 0) {
                String dirPath = rootPath.concat(String.valueOf(partCounter));
                String filePartName = String.format("%s-%s.%d", fileName, hashUsername, partCounter++);
                File newFile = new File(dirPath, filePartName);
                try (FileOutputStream out = new FileOutputStream(newFile)) {
                    out.write(buffer, 0, bytesAmount);
                }
                encryptFile(newFile,newFile);
            }
        }
    }

    public void encryptFile(File input, File output) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,userKeyPair.getPublic());
        byte[] data = new byte[(int)input.length()];
        try(FileInputStream fis = new FileInputStream(input)) {
            fis.read(data,0,(int)input.length());
        }
        List<byte[]> byteList = divideArray(data,245);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for(byte[] array: byteList) {
            outputStream.write(cipher.doFinal(array));
        }
        byte[] encryptedBytes = outputStream.toByteArray();
        Files.write(output.toPath(),encryptedBytes);
    }

    public static List<byte[]> divideArray(byte[] source, int chunksize) {
        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }
        return result;
    }

    public void decryptFile(File input, File output) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, userKeyPair.getPrivate());
        byte[] data = new byte[(int) input.length()];
        try (FileInputStream fis = new FileInputStream(input)) {
            fis.read(data, 0, (int) input.length());
        }
        List<byte[]> byteList = divideArray(data, 256);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] array : byteList) {
            outputStream.write(cipher.doFinal(array));
        }
        byte[] decryptedBytes = outputStream.toByteArray();
        Files.write(output.toPath(), decryptedBytes);

        }




    @FXML
    void btnShowClicked(ActionEvent event) throws Exception {
        if(selectedFile == null) {
            lblMsgFile.setText("Please choose file from list.");
        }
        else {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(txtUsername.getText().getBytes(StandardCharsets.UTF_8));
            String hashUsername = String.format("%064x", new BigInteger(1, hash));
            String endFilePath = System.getProperty("user.dir") + File.separator +
                    "currentFile"+File.separator + selectedFile;
            File endFile = new File(endFilePath);
            OutputStream outputStream = createAppendableStream(endFile);
            File dirPath = new File(System.getProperty("user.dir") + File.separator +
                    "root" + File.separator );
            String[] contents = dirPath.list();
            for (String content : contents) {
                if (content.contains("dir")) {
                    String subDirPath = System.getProperty("user.dir") + File.separator +
                            "root" + File.separator  + content;
                    File subDir = new File(subDirPath);
                    String[] subContents = subDir.list();
                    for (String subContent : subContents) {
                        if (subContent.contains(selectedFile)) {
                            if (subContent.contains(hashUsername)) {
                                String filePartPath = subDirPath + File.separator + subContent;
                                File filePart = new File(filePartPath);
                                File tempFile = new File(System.getProperty("user.dir") + File.separator +
                                        "currentPart" + File.separator +  subContent);
                                decryptFile(filePart, tempFile);
                                appendFile(outputStream, tempFile);
                                tempFile.delete();
                            }
                        }
                    }
                }
            }
            closeFile(outputStream);
            MessageDigest digest1 = MessageDigest.getInstance("SHA-256");
            byte[] hash1 = digest1.digest(Files.readAllBytes(endFile.toPath()));
            String hashFile = String.format("%064x", new BigInteger(1, hash1));
            if (findHash(hashFile)) {
                lblMsgFile.setText("File is valid and uncorrupted.");
            } else {
                lblMsgFile.setText("File is non valid and corrupted.");
            }
            byte[] array = Files.readAllBytes(endFile.toPath());
            File decryptedFile = new File(System.getProperty("user.dir") + File.separator + "endFiles"+ File.separator + selectedFile );
            Files.write(decryptedFile.toPath(),array);
            endFile.delete();
        }
    }

    public boolean findHash(String hash) throws IOException{
        boolean equal = false;
        List<String> fileContent = new ArrayList<>(Files.readAllLines(Path.of(userPath), StandardCharsets.UTF_8));
        for (int i = 0; i < fileContent.size(); i++) {
            if (fileContent.get(i).contains(txtUsername.getText())) {
                if (fileContent.get(i).contains(selectedFile)) {
                    String[] array = fileContent.get(i).split("%");
                    for(int j=0; j < array.length ; j++) {
                       if(array[j].equals(selectedFile)) {
                           equal = array[j+1].equals(hash);
                           break;
                       }
                    }
                }
            }
        }
        return equal;
    }

    private static BufferedOutputStream createAppendableStream(File destination)
            throws FileNotFoundException {
        return new BufferedOutputStream(new FileOutputStream(destination, true));
    }

    private static void appendFile(OutputStream output, File source)
            throws IOException {
        InputStream input = null;
        try {
            input = new BufferedInputStream(new FileInputStream(source));
            copy(input, output);
        } finally {
            closeFile(input);
        }
    }

    public static long copy(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[1024*4];
        long count = 0;
        int n = 0;
        while (-1 != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }

    public static void closeFile(Closeable output) {
        try {
            if (output != null) {
                output.close();
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }



    public void listViewSelectedFile() {
        selectedFile = listView.getSelectionModel().getSelectedItem();
    }

    public boolean checkPassword(String password, String username) throws IOException, NoSuchAlgorithmException {
        boolean check = false;

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        String hashPassword = String.format("%064x", new BigInteger(1, hash));

        List<String> fileContent = new ArrayList<>(Files.readAllLines(Path.of(userPath), StandardCharsets.UTF_8));

        for (int i = 0; i < fileContent.size(); i++) {
            if (fileContent.get(i).contains(username)) {
                String array[] = fileContent.get(i).split("%");
                if(array[1].equals(hashPassword))
                    check = true;
                    break;
            }
        }
        return check;
    }

    public void updateCRList(X509Certificate userCert) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        File caFile = new File(caCertPath);
        FileInputStream fis = new FileInputStream(caFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);
        X500Name caName = new X500Name(caCert.getSubjectX500Principal().getName());
        File caKeyDer = new File(caKeyPath);
        KeyPair caKeyPair = new KeyPair(caCert.getPublicKey(),readPrivateKey(caKeyDer));

        Calendar c = Calendar.getInstance();
        c.setTime(Calendar.getInstance().getTime());
        c.add(Calendar.DATE, 7);
        Date updateDate = c.getTime();

        File crlFile = new File(crListPath);
        FileInputStream crlFileInputStream = new FileInputStream(crlFile);
        ASN1InputStream asn1Stream = new ASN1InputStream(crlFileInputStream.readAllBytes());
        X509CRLHolder crlPrevHolder = new X509CRLHolder(asn1Stream);
        X509CRL crlPrev = new JcaX509CRLConverter().getCRL(crlPrevHolder);
        asn1Stream.close();


        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caName, Calendar.getInstance().getTime());
        crlBuilder.setNextUpdate(updateDate);
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        CRLReason crlReason = CRLReason.lookup(CRLReason.certificateHold);
        extGen.addExtension(Extension.reasonCode,false,crlReason);
        crlBuilder.addCRLEntry(userCert.getSerialNumber(),new Date(),extGen.generate());
        crlBuilder.addCRL(crlPrevHolder);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));
        ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).setProvider(provider).build(caKeyPair.getPrivate());
        X509CRLHolder crlHolder = crlBuilder.build(contentSigner);

        CertificateFactory crlf = CertificateFactory.getInstance("X.509", "BC");
        X509CRL crl = (X509CRL) crlf.generateCRL(new ByteArrayInputStream(crlHolder.getEncoded()));

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(b);
        CertificateList certificateList = CertificateList.getInstance(crl.getEncoded());
        asn1OutputStream.writeObject(certificateList);
        byte[] derData = b.toByteArray();

        OutputStream outputStream = new FileOutputStream(crlFile);
        outputStream.write(derData);
        outputStream.close();
    }

    public void createCRList(X509Certificate userCert) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        File caFile = new File(caCertPath);
        FileInputStream fis = new FileInputStream(caFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);
        X500Name caName = new X500Name(caCert.getSubjectX500Principal().getName());
        File caKeyDer = new File(caKeyPath);
        KeyPair caKeyPair = new KeyPair(caCert.getPublicKey(),readPrivateKey(caKeyDer));

        Calendar c = Calendar.getInstance();
        c.setTime(Calendar.getInstance().getTime());
        c.add(Calendar.DATE, 7);
        Date updateDate = c.getTime();


        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caName, Calendar.getInstance().getTime());
        crlBuilder.setNextUpdate(updateDate);
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        CRLReason crlReason = CRLReason.lookup(CRLReason.certificateHold);
        extGen.addExtension(Extension.reasonCode,false,crlReason);
        crlBuilder.addCRLEntry(userCert.getSerialNumber(),new Date(),extGen.generate());
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));
        ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).setProvider(provider).build(caKeyPair.getPrivate());
        X509CRLHolder crlHolder = crlBuilder.build(contentSigner);

        CertificateFactory crlf = CertificateFactory.getInstance("X.509", "BC");
        X509CRL crl = new JcaX509CRLConverter().setProvider(provider).getCRL(crlHolder);

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(b);
        CertificateList certificateList = CertificateList.getInstance(crl.getEncoded());
        asn1OutputStream.writeObject(certificateList);
        byte[] derData = b.toByteArray();

        OutputStream outputStream = new FileOutputStream(crListPath);
        outputStream.write(derData);
        outputStream.close();
    }

    public void refreshCRL(X509CRL prevCRL) throws CRLException, IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(b);
        CertificateList certificateList = CertificateList.getInstance(prevCRL.getEncoded());
        asn1OutputStream.writeObject(certificateList);
        byte[] derData = b.toByteArray();

        OutputStream outputStream = new FileOutputStream(crListPath);
        outputStream.write(derData);
        outputStream.close();
    }

    public X509CRL getCurrentCRL() throws IOException, CRLException {
        File file = new File(System.getProperty("user.dir") + File.separator +
                "root" + File.separator +"cert" + File.separator + "crl");
        if (Objects.requireNonNull(file.list()).length==0) {
            return null;
        }
        else {
            File crlFile = new File(crListPath);
            FileInputStream crlFileInputStream = new FileInputStream(crlFile);
            ASN1InputStream asn1Stream = new ASN1InputStream(crlFileInputStream.readAllBytes());
            X509CRLHolder crlHolder = new X509CRLHolder(asn1Stream);
            X509CRL currentCrl = new JcaX509CRLConverter().getCRL(crlHolder);
            return currentCrl;
        }

    }
}

