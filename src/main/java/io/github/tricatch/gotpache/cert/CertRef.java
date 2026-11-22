package io.github.tricatch.gotpache.cert;

import java.math.BigInteger;
import java.security.SecureRandom;

class CertRef {

    public static final String BC_PROVIDER = "BC";
    public static final String KEY_ALGORITHM = "RSA";
    public static final int KEY_SIZE = 2048;
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static final long DAY_MSEC = 1000L * 24 * 60 * 60;

    public static final long DAY_FOR_CA = 365 * 10;
    public static final long DAY_FOR_SSL = 180;

    /** RFC 5280 ub-common-name. */
    public static final int MAX_COMMON_NAME_LENGTH = 64;
    /** Subject of a certificate whose domain does not fit in a common name; the SAN names the domain. */
    public static final String LONG_DOMAIN_COMMON_NAME = "gotpache-keytool";

    private static final SecureRandom RANDOM = new SecureRandom();

    /** A random serial number that is positive and well inside the 20 octets RFC 5280 allows. */
    static BigInteger newSerialNumber() {
        return new BigInteger(127, RANDOM).add(BigInteger.ONE);
    }
}
