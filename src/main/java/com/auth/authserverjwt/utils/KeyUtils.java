package com.auth.authserverjwt.utils;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public abstract class KeyUtils {
    private KeyUtils() {}

    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    public static PrivateKey getSignInKey() {
        try {
            String privateKeyPem = System.getenv("SECRET_KEY").replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);

        } catch (Exception e) {
            //Specific exception?
            throw new RuntimeException();
        }
    }

    public static PublicKey getPublicKeyFromPrivateKey(PrivateKey privateKey) {
        try {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            BigInteger modulus = rsaPrivateKey.getModulus();

            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, PUBLIC_EXPONENT);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive public key from private key", e);
        }
    }
}
