package io.github.tricatch.gotpache.cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Generate an SSL certificate. A root certificate is required to create an SSL certificate.
 * If the root certificate is not available,
 * use the RootCertificateCreator to generate the root certificate first.
 */
public class SSLCertificateCreator {

    /**
     * Generate an SSL certificate.
     * @param domain Domain for the SSL certificate (e.g., foo.kr, www.foo.kr)
     * @param rootCertificate Root certificate for issuing SSL certificate
     * @param rootPrivateKey Root private key for signing the SSL certificate.
     * @return Return the certificate, public key, and private key as the response.
     * @throws GotpacheCertException Wrap the exceptions that occur during the certificate generation process. Refer to the Root Cause for more information.
     */
    public CertificateKeyPair generateSSLCertificate(String domain, X509Certificate rootCertificate, PrivateKey rootPrivateKey) throws GotpacheCertException {

        try {

            initProvider();

            X500Name sslCN = new X500Name("CN=" + domain);
            X500Name rootCN = new X500Name(rootCertificate.getIssuerDN().getName());

            BigInteger serialNo = new BigInteger(Long.toString(new SecureRandom().nextLong()));
            Date startDt = new Date(System.currentTimeMillis() - CertRef.DAY_MSEC);
            Date endDt = new Date(startDt.getTime() + (CertRef.DAY_MSEC * CertRef.DAY_FOR_SSL));

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CertRef.KEY_ALGORITHM, CertRef.BC_PROVIDER);
            keyPairGenerator.initialize(CertRef.KEY_SIZE);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey pubKey = keyPair.getPublic();
            PrivateKey priKey = keyPair.getPrivate();

            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    sslCN
                    , pubKey
            );

            JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(CertRef.SIGNATURE_ALGORITHM)
                    .setProvider(CertRef.BC_PROVIDER);

            ContentSigner csrContentSigner = csrBuilder.build(rootPrivateKey);

            PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

            X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(
                    rootCN
                    , serialNo
                    , startDt
                    , endDt
                    , csr.getSubject()
                    , csr.getSubjectPublicKeyInfo()
            );

            JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

            issuedCertBuilder.addExtension(
                    Extension.basicConstraints
                    , true
                    , new BasicConstraints(false)
            );

            issuedCertBuilder.addExtension(
                    Extension.authorityKeyIdentifier
                    , false
                    , issuedCertExtUtils.createAuthorityKeyIdentifier(rootCertificate)
            );

            issuedCertBuilder.addExtension(
                    Extension.subjectKeyIdentifier
                    , false
                    , issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo())
            );

            issuedCertBuilder.addExtension(
                    Extension.keyUsage
                    , false
                    , new KeyUsage(KeyUsage.digitalSignature)
            );

            issuedCertBuilder.addExtension(
                    Extension.subjectAlternativeName
                    , false
                    , new DERSequence(
                            new ASN1Encodable[]{
                                    new GeneralName(GeneralName.dNSName, domain)
                                    , new GeneralName(GeneralName.iPAddress, "127.0.0.1")})
            );

            X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);

            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider(CertRef.BC_PROVIDER)
                    .getCertificate(issuedCertHolder);

            certificate.verify(rootCertificate.getPublicKey(), CertRef.BC_PROVIDER);

            return new CertificateKeyPair(
                    certificate
                    , pubKey
                    , priKey
            );

        } catch (CertificateException
                 | NoSuchAlgorithmException
                 | NoSuchProviderException
                 | IOException
                 | OperatorCreationException
                 | InvalidKeyException
                 | SignatureException e
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
