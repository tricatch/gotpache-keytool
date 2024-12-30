package io.github.tricatch.gotpache.cert;

class CertRef {

    public static final String BC_PROVIDER = "BC";
    public static final String KEY_ALGORITHM = "RSA";
    public static final int KEY_SIZE = 2048;
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static final long DAY_MSEC = 1000L * 24 * 60 * 60;

    public static final long DAY_FOR_CA = 365 * 10;
    public static final long DAY_FOR_SSL = 180;
}
