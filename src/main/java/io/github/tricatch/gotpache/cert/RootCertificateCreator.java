package io.github.tricatch.gotpache.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Create a root certificate authority (CA) for generating SSL certificates.
 * The BC (Bouncy Castle) provider is required for certificate generation.
 */
public class RootCertificateCreator {

    /**
     * Generate a root certificate authority (CA).
     *
     * @param rootAlias Root Certificate Alias
     * @return Return the certificate, public key, and private key as the response.
     * @throws GotpacheCertException Wrap the exceptions that occur during the certificate generation process. Refer to the Root Cause for more information.
     */
    public CertificateKeyPair generateRootCertificate(String rootAlias) throws GotpacheCertException {

        try {
            initProvider();

            X500Name rootCN = new X500Name("CN=" + rootAlias);

            BigInteger serialNo = new BigInteger(Long.toString(new SecureRandom().nextLong()));
            Date startDt = new Date(System.currentTimeMillis() - CertRef.DAY_MSEC);
            Date endDt = new Date(startDt.getTime() + (CertRef.DAY_MSEC * CertRef.DAY_FOR_CA));

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CertRef.KEY_ALGORITHM, CertRef.BC_PROVIDER);
            keyPairGenerator.initialize(CertRef.KEY_SIZE);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey pubKey = keyPair.getPublic();
            PrivateKey priKey = keyPair.getPrivate();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    rootCN
                    , serialNo
                    , startDt
                    , endDt
                    , rootCN
                    , pubKey
            );

            certBuilder.addExtension(
                    Extension.basicConstraints
                    , true
                    , new BasicConstraints(true)
            );

            certBuilder.addExtension(
                    Extension.subjectKeyIdentifier
                    , false
                    , new JcaX509ExtensionUtils().createSubjectKeyIdentifier(pubKey)
            );

            KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
            ExtensionsGenerator eg = new ExtensionsGenerator();
            eg.addExtension(Extension.keyUsage, true, ku);

            certBuilder.addExtension(Extension.keyUsage, true, ku);

            ContentSigner contentSigner = new JcaContentSignerBuilder(CertRef.SIGNATURE_ALGORITHM)
                    .setProvider(CertRef.BC_PROVIDER)
                    .build(priKey);

            X509CertificateHolder certHolder = certBuilder.build(contentSigner);

            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider(CertRef.BC_PROVIDER)
                    .getCertificate(certHolder);

            return new CertificateKeyPair(
                    certificate
                    , pubKey
                    , priKey
            );

        } catch (CertificateException
                 | NoSuchAlgorithmException
                 | NoSuchProviderException
                 | IOException
                 | OperatorCreationException e
        ) {
            throw new GotpacheCertException(e);
        }
    }

    private void initProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
