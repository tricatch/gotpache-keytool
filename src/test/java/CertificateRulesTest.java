import io.github.tricatch.gotpache.cert.CertificateKeyPair;
import io.github.tricatch.gotpache.cert.RootCertificateCreator;
import io.github.tricatch.gotpache.cert.SSLCertificateCreator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CertificateRulesTest {

    private final SSLCertificateCreator creator = new SSLCertificateCreator();

    @Test
    void issuerIsTheByteExactSubjectOfAMultiRdnRoot() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair key = generator.generateKeyPair();
        X500Name name = new X500Name("C=KR,O=Test Org,CN=Multi RDN Root");
        Date from = new Date(System.currentTimeMillis() - 2 * 86_400_000L);
        Date to = new Date(System.currentTimeMillis() + 400 * 86_400_000L);
        X509Certificate root = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(name, BigInteger.ONE, from, to, name, key.getPublic())
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())));

        X509Certificate leaf = creator.generateSSLCertificate("app.example.test", root, key.getPrivate()).getCertificate();

        assertArrayEquals(root.getSubjectX500Principal().getEncoded(), leaf.getIssuerX500Principal().getEncoded());
        validate(root, leaf);
    }

    @Test
    void namesLongerThanTheCommonNameLimitAreCarriedBySan() throws Exception {
        CertificateKeyPair root = new RootCertificateCreator().generateRootCertificate("Test Root");
        StringBuilder label = new StringBuilder();
        for (int i = 0; i < 60; i++) label.append('a');
        String[] domains = {
                label.substring(0, 51) + ".example.test", // 64
                label.substring(0, 52) + ".example.test", // 65
                label + "." + label + "." + label + ".example.test"};

        for (String domain : domains) {
            X509Certificate leaf = creator.generateSSLCertificate(domain, root.getCertificate(), root.getPrivateKey()).getCertificate();
            assertTrue(hasDnsName(leaf, domain), domain);
            String commonName = X500Name.getInstance(leaf.getSubjectX500Principal().getEncoded())
                    .getRDNs()[0].getFirst().getValue().toString();
            assertTrue(commonName.length() <= 64, commonName);
            validate(root.getCertificate(), leaf);
        }
    }

    @Test
    void aDomainCannotInjectAttributesIntoTheSubject() throws Exception {
        CertificateKeyPair root = new RootCertificateCreator().generateRootCertificate("Test Root");
        X509Certificate leaf = creator.generateSSLCertificate("app.test,O=Injected", root.getCertificate(), root.getPrivateKey()).getCertificate();
        assertEquals(1, X500Name.getInstance(leaf.getSubjectX500Principal().getEncoded()).getRDNs().length);
    }

    @Test
    void leafIsAServerCertificate() throws Exception {
        CertificateKeyPair root = new RootCertificateCreator().generateRootCertificate("Test Root");
        X509Certificate leaf = creator.generateSSLCertificate("app.example.test", root.getCertificate(), root.getPrivateKey()).getCertificate();

        assertEquals(Collections.singletonList("1.3.6.1.5.5.7.3.1"), leaf.getExtendedKeyUsage());
        assertTrue(leaf.getKeyUsage()[0], "digitalSignature");
        assertTrue(leaf.getKeyUsage()[2], "keyEncipherment");
        assertEquals(-1, leaf.getBasicConstraints());
    }

    @Test
    void serialNumbersArePositiveAndAtMostTwentyOctets() throws Exception {
        CertificateKeyPair root = new RootCertificateCreator().generateRootCertificate("Test Root");
        // A random signed long is negative half the time: 8 + 8 draws miss that once in 65536 runs.
        for (int i = 0; i < 8; i++) {
            assertValidSerial(new RootCertificateCreator().generateRootCertificate("Test Root").getCertificate().getSerialNumber());
            assertValidSerial(creator.generateSSLCertificate("app.example.test", root.getCertificate(), root.getPrivateKey())
                    .getCertificate().getSerialNumber());
        }
    }

    @Test
    void rootsIssuedByVersion010WithANegativeSerialStillSign() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair key = generator.generateKeyPair();
        X500Name name = new X500Name("CN=Old Root");
        Date from = new Date(System.currentTimeMillis() - 2 * 86_400_000L);
        Date to = new Date(System.currentTimeMillis() + 400 * 86_400_000L);
        X509Certificate root = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(-1234567890123L), from, to, name, key.getPublic())
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())));

        validate(root, creator.generateSSLCertificate("app.example.test", root, key.getPrivate()).getCertificate());
    }

    private static void assertValidSerial(BigInteger serial) {
        assertTrue(serial.signum() > 0, serial.toString());
        assertTrue(serial.toByteArray().length <= 20, serial.toString());
    }

    private static boolean hasDnsName(X509Certificate certificate, String name) throws Exception {
        Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        for (List<?> san : names) {
            if (Integer.valueOf(2).equals(san.get(0)) && name.equals(san.get(1))) return true;
        }
        return false;
    }

    private static void validate(X509Certificate root, X509Certificate leaf) throws Exception {
        PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(root, null)));
        parameters.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX").validate(
                CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(leaf)), parameters);
    }
}
