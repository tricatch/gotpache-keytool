import io.github.tricatch.gotpache.cert.CertificateKeyPair;
import io.github.tricatch.gotpache.cert.KeyTool;
import io.github.tricatch.gotpache.cert.RootCertificateCreator;
import io.github.tricatch.gotpache.cert.SSLCertificateCreator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class CertResourceTest {

    public static void main(String[] args) {

        String path = "./certs";
        String fCa = "ca.crt";
        String fPubKey = "pub.key";
        String fPriKey = "pri.key";
        String fPriKeyEnc = "priEnc.key";
        String fRootCert = "root.crt";
        String fRootKey = "root.key";
        Path resources = null;

        try {

            KeyTool keyTool = new KeyTool();

            // A new root each run, on the classpath only while it runs: never commit a private key.
            Path classpathRoot = Paths.get(CertResourceTest.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            resources = Files.createTempDirectory(classpathRoot, "localtest");
            CertificateKeyPair root = new RootCertificateCreator().generateRootCertificate("Test Root");
            keyTool.writeCertificate(root.getCertificate(), resources.toString(), fRootCert);
            keyTool.writePrivateKey(root.getPrivateKey(), "pwd", resources.toString(), fRootKey);

            String prefix = resources.getFileName() + "/";
            X509Certificate rootCert = keyTool.readCertificate(CertResourceTest.class, prefix + fRootCert);
            PrivateKey rootPrivateKey = keyTool.readPrivateKey(CertResourceTest.class, prefix + fRootKey, "pwd");

            SSLCertificateCreator sslCertificateCreator = new SSLCertificateCreator();

            CertificateKeyPair sslCert = sslCertificateCreator.generateSSLCertificate("foo.kr", rootCert, rootPrivateKey);


            keyTool.writeCertificate(sslCert.getCertificate(), path, fCa);
            keyTool.writePublicKey(sslCert.getPublicKey(), path, fPubKey);
            keyTool.writePrivateKey(sslCert.getPrivateKey(), path, fPriKey);
            keyTool.writePrivateKey(sslCert.getPrivateKey(), "password", path, fPriKeyEnc);

            X509Certificate certificate = keyTool.readCertificate(path, fCa);
            PublicKey publicKey = keyTool.readPublicKey(path, fPubKey);
            PrivateKey privateKey = keyTool.readPrivateKey(path, fPriKey);
            PrivateKey privateKeyEnc = keyTool.readPrivateKey(path, fPriKeyEnc, "password" );

            byte[] data = "HELLO".getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = keyTool.sign(data, privateKey);
            byte[] encSignatureBytes = keyTool.sign(data, privateKeyEnc);

            if( !keyTool.verify(data, signatureBytes, certificate.getPublicKey()) ) {
                throw new Exception("error - verify with certificate" );
            }

            if( !keyTool.verify(data, signatureBytes, publicKey) ) {
                throw new Exception("error - verify with publicKey" );
            }

            if( !keyTool.verify(data, encSignatureBytes, certificate.getPublicKey()) ) {
                throw new Exception("error - verifyEnc with certificate" );
            }

            if( !keyTool.verify(data, encSignatureBytes, publicKey) ) {
                throw new Exception("error - verifyEnc with publicKey" );
            }

            System.out.println("DONE");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            delete(path, fCa);
            delete(path, fPubKey);
            delete(path, fPriKey);
            delete(path, fPriKeyEnc);
            if (resources != null) {
                delete(resources.toString(), fRootCert);
                delete(resources.toString(), fRootKey);
                delete(resources.toString(), "");
            }
        }
    }

    private static void delete(String path, String filename){

        try{

            Files.delete( Paths.get(path, filename) );

        }catch (Exception e){
            //nothing
        }
    }

}
