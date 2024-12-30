package io.github.tricatch.gotpache.cert;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class CertificateKeyPair {

    private final X509Certificate certificate;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public CertificateKeyPair(X509Certificate certificate, PublicKey publicKey, PrivateKey privateKey) {
        this.certificate = certificate;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
