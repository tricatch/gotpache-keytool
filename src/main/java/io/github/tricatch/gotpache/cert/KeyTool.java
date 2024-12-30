package io.github.tricatch.gotpache.cert;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * ROOT certificates provide functionality to write, read, and generate SSL certificates.
 */
public class KeyTool {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public String toPem(X509Certificate certificate) throws IOException {

        Writer writer = new StringWriter();

        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(certificate);
        }

        return writer.toString();
    }

    public String toPem(PublicKey publicKey) throws IOException {

        Writer writer = new StringWriter();

        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(publicKey);
        }

        return writer.toString();
    }

    public String toPem(PrivateKey privateKey) throws IOException {

        Writer writer = new StringWriter();

        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());

        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            PKCS8Generator generator = new PKCS8Generator(privateKeyInfo, null);
            pemWriter.writeObject(generator);
        }

        return writer.toString();
    }

    public String toPem(PrivateKey privateKey, String password) throws IOException, GotpacheCertException {

        try {
            Writer writer = new StringWriter();

            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());

            OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                    .setProvider("BC")
                    .setRandom(new java.security.SecureRandom())
                    .setPassword(password.toCharArray())
                    .build();

            try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                PKCS8Generator generator = new PKCS8Generator(privateKeyInfo, encryptor);
                pemWriter.writeObject(generator);
            }

            return writer.toString();
        }catch (OperatorCreationException e){
            throw new GotpacheCertException(e);
        }
    }

    public X509Certificate toCertificate(String pemCertificate) throws IOException, CertificateException {

        try (
                Reader reader = new StringReader(pemCertificate);
                PemReader pemReader = new PemReader(reader);
        ) {
            PemObject pemObject = pemReader.readPemObject();

            if (pemObject == null) {
                throw new IOException("Invalid certificate PEM");
            }

            byte[] certBytes = pemObject.getContent();

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            try (ByteArrayInputStream certInputStream = new ByteArrayInputStream(certBytes)) {
                Certificate certificate = certificateFactory.generateCertificate(certInputStream);
                return (X509Certificate) certificate;
            }
        }
    }

    public PublicKey toPublicKey(String pemPublicKey) throws IOException {

        try (
                Reader reader = new StringReader(pemPublicKey);
                PEMParser pemParser = new PEMParser(reader);
        ) {

            Object object = pemParser.readObject();

            if (object instanceof SubjectPublicKeyInfo) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getPublicKey((SubjectPublicKeyInfo) object);
            } else {
                throw new IllegalArgumentException("Invalid publicKey PEM");
            }
        }
    }


    public PrivateKey toPrivateKey(String pemPrivateKey) throws IOException {

        try (
                Reader reader = new StringReader(pemPrivateKey);
                PEMParser pemParser = new PEMParser(reader);
        ) {

            Object keyObj = pemParser.readObject();

            if (keyObj instanceof PrivateKeyInfo) {

                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getPrivateKey((PrivateKeyInfo)keyObj);

            } else {
                throw new IllegalArgumentException("Invalid privateKey PEM");
            }
        }
    }

    public PrivateKey toPrivateKey(String pemPrivateKey, String password) throws IOException, GotpacheCertException {

        try (
                Reader reader = new StringReader(pemPrivateKey);
                PEMParser pemParser = new PEMParser(reader);
        ) {

            Object keyObj = pemParser.readObject();

            if (keyObj instanceof PKCS8EncryptedPrivateKeyInfo) {

                PKCS8EncryptedPrivateKeyInfo encPriKeyInfo = (PKCS8EncryptedPrivateKeyInfo) keyObj;

                PrivateKeyInfo privateKeyInfo = encPriKeyInfo.decryptPrivateKeyInfo(
                        new JceOpenSSLPKCS8DecryptorProviderBuilder()
                                .build(password.toCharArray())
                );

                return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);

            } else {
                throw new IllegalArgumentException("Invalid encPrivateKey PEM");
            }
        }catch (OperatorCreationException | PKCSException e){
            throw new GotpacheCertException(e);
        }
    }


    public void writeCertificate(X509Certificate certificate, String path, String filename) throws IOException {

        String pem = toPem(certificate);
        writePem(pem, path, filename);
    }

    public void writePublicKey(PublicKey publicKey, String path, String filename) throws IOException {

        String pem = toPem(publicKey);
        writePem(pem, path, filename);
    }

    public void writePrivateKey(PrivateKey privateKey, String path, String filename) throws IOException {

        String pem = toPem(privateKey);
        writePem(pem, path, filename);
    }

    public void writePrivateKey(PrivateKey privateKey, String password, String path, String filename) throws IOException, GotpacheCertException {

        String pem = toPem(privateKey, password);
        writePem(pem, path, filename);
    }

    public X509Certificate readCertificate(String path, String filename) throws IOException, CertificateException {

        String pem = readPem(path, filename);

        return toCertificate(pem);
    }

    public PublicKey readPublicKey(String path, String filename) throws IOException {

        String pem = readPem(path, filename);

        return toPublicKey(pem);
    }


    public PrivateKey readPrivateKey(String path, String filename) throws IOException {

        String pem = readPem(path, filename);

        return toPrivateKey(pem);
    }

    public PrivateKey readPrivateKey(String path, String filename, String password) throws IOException, GotpacheCertException {

        String pem = readPem(path, filename);

        return toPrivateKey(pem, password);
    }

    public X509Certificate readCertificate(Class<?> refClass, String resource) throws IOException, CertificateException {

        String pem = readPem(refClass, resource);

        return toCertificate(pem);
    }

    public PublicKey readPublicKey(Class<?> refClass, String resource) throws IOException {

        String pem = readPem(refClass, resource);

        return toPublicKey(pem);
    }


    public PrivateKey readPrivateKey(Class<?> refClass, String resource) throws IOException {

        String pem = readPem(refClass, resource);

        return toPrivateKey(pem);
    }

    public PrivateKey readPrivateKey(Class<?> refClass, String resource, String password) throws IOException, GotpacheCertException {

        String pem = readPem(refClass, resource);

        return toPrivateKey(pem, password);
    }


    public byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature signature = Signature.getInstance(CertRef.SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);

        signature.update(data);

        return signature.sign();
    }

    public boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature signature = Signature.getInstance(CertRef.SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);

        signature.update(data);

        return signature.verify(signatureBytes);
    }

    private void writePem(String pem, String path, String filename) throws IOException {

        Path filePath = Paths.get(path, filename);

        try (
                FileOutputStream fout = new FileOutputStream(filePath.toFile());
        ) {
            fout.write(pem.getBytes(StandardCharsets.UTF_8));
        }
    }

    private String readPem(String path, String filename) throws IOException {

        Path filePath = Paths.get(path, filename);

        byte[] buf = Files.readAllBytes(filePath);

        return new String(buf, StandardCharsets.UTF_8);
    }

    private String readPem(Class<?> refClass, String resource) throws IOException {

        InputStream inputStream = refClass.getClassLoader().getResourceAsStream(resource);

        if (inputStream == null) {
           throw new FileNotFoundException("resource not found - " + resource);
        }

        StringBuilder pem = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            for(;;){
                String line = reader.readLine();
                if( line == null ) break;
                if( pem.length()>0 ) pem.append("\n");
                pem.append(line);
            }
        }

        return pem.toString();
    }

    public static void main(String[] args){

        if( args.length==3 && "-root".equals(args[0]) ){
            //good
        } else if( args.length==5 && "-ssl".equals(args[0]) ){
            //good
        } else {
            usage();
            return;
        }

        String cmd = args[0];

        try {

            if( "-root".equals(cmd) ) {
                String rootAlias = args[1];
                String rootPwd = args[2];
                String path = "./";
                StringBuilder caCertFile = new StringBuilder(rootAlias).append(".crt");
                StringBuilder caPriKeyFile = new StringBuilder(rootAlias).append(".key");

                RootCertificateCreator rootCertificateCreator = new RootCertificateCreator();
                CertificateKeyPair certificateKeyPair = rootCertificateCreator.generateRootCertificate(rootAlias);

                KeyTool keyTool = new KeyTool();

                keyTool.writeCertificate(certificateKeyPair.getCertificate(), path, caCertFile.toString());
                keyTool.writePrivateKey(certificateKeyPair.getPrivateKey(), rootPwd, path, caPriKeyFile.toString());

                System.out.println( "--- root certificate / privateKey ---" );
                System.out.println( caCertFile );
                System.out.println( caPriKeyFile );

            }

            if( "-ssl".equals(cmd) ){
                String rootAlias = args[1];
                String rootPwd = args[2];
                String sslDomain = args[3];
                String sslPwd = args[4];

                String path = "./";
                StringBuilder caCertFile = new StringBuilder(rootAlias).append(".crt");
                StringBuilder caPriKeyFile = new StringBuilder(rootAlias).append(".key");
                StringBuilder sslCertFile = new StringBuilder(sslDomain).append(".crt");
                StringBuilder sslPriKeyFile = new StringBuilder(sslDomain).append(".key");

                KeyTool keyTool = new KeyTool();
                X509Certificate caCertificate = keyTool.readCertificate(path, caCertFile.toString() );
                PrivateKey caPrivateKey = keyTool.readPrivateKey(path, caPriKeyFile.toString(), rootPwd);

                SSLCertificateCreator sslCertificateCreator = new SSLCertificateCreator();
                CertificateKeyPair certificateKeyPair = sslCertificateCreator.generateSSLCertificate(sslDomain, caCertificate, caPrivateKey);

                keyTool.writeCertificate(certificateKeyPair.getCertificate(), path, sslCertFile.toString());
                keyTool.writePrivateKey(certificateKeyPair.getPrivateKey(), sslPwd, path, sslPriKeyFile.toString());

                System.out.println( "--- ssl certificate / privateKey ---" );
                System.out.println( sslCertFile );
                System.out.println( sslPriKeyFile );
            }

        }catch (Exception e){
            System.out.println( "ERROR - " + e.getMessage() );
            e.printStackTrace();
        }
    }

    private static void usage() {
        System.out.println("");
        System.out.println("KeyTool Usage");
        System.out.println("-root {rootAlias} {rootPwd}");
        System.out.println("-ssl  {rootAlias} {rootPwd} {sslDomain} {sslPwd}");
    }
}