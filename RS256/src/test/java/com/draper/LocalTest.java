package com.draper;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import sun.security.rsa.RSAPublicKeyImpl;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.UUID;

public class LocalTest {
    @Test
    public void testCreateToken() throws IOException {
        System.out.println(createToken());
    }

    @Test
    public void testVerifyToken() throws Exception {
        String token = createToken();
        System.out.println(token);

        JwtClaims jwtClaims = verifyToken(token);
        System.out.println(jwtClaims.getClaimValue("name"));
        System.out.println(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(jwtClaims.getIssuedAt().getValueInMillis()));
        System.out.println(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(jwtClaims.getExpirationTime().getValueInMillis()));
    }

    /**
     * 生成jwt,SHA256加密
     * @return
     * @throws IOException
     */
    private String createToken() throws IOException {
        PrivateKey privateKey = getPrivateKey(getPrivateKeyString());
        final JwtClaims claims = new JwtClaims();
        claims.setClaim("name", "jack");
        claims.setSubject("a@a.com");
        claims.setAudience("test");//用于验证签名是否合法，验证方必须包含这些内容才验证通过
        claims.setExpirationTimeMinutesInTheFuture(60*24*30);
        claims.setIssuedAtToNow();

        // Generate the payload
        final JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload(claims.toJson());
        jws.setKeyIdHeaderValue(UUID.randomUUID().toString());

        System.out.println("1");
        // Sign using the private key
        jws.setKey(privateKey);
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            e.printStackTrace();
            System.out.println("1.null");
            return null;
        }
    }

    /**
     * 验证jwt
     * @param token
     * @return
     * @throws Exception
     */
    private JwtClaims verifyToken(String token) throws Exception {

        try {
            PublicKey publicKey = getPublicKey(getPEMPublicKeyString());

            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setRequireExpirationTime()
                    .setVerificationKey(publicKey)
                    .setExpectedAudience("test")//用于验证签名是否合法，可以设置多个，且可设置必须存在项，如果jwt中不包含这些内容则不通过
                    .build();

            return jwtConsumer.processToClaims(token);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getPrivateKeyString() throws IOException {
        //    生成方法：安装openssl,执行     openssl genrsa -out private.pem 2048
        String privateKey = IOUtils.toString(new FileInputStream("src/main/resource/private.pem"));
        return privateKey;
    }

    @Test
    public void testGetPrivateKeyString() throws IOException {
        System.out.println(getPrivateKeyString());
    }

    private String getPEMPublicKeyString() throws IOException {
        //    导出公钥方法：生成私钥(private.pem)后,执行    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
        return IOUtils.toString(new FileInputStream("src/main/resource/public.pem"));
    }

    /**
     * 获取PublicKey对象
     * @param publicKeyBase64
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private PublicKey getPublicKey(String publicKeyBase64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String pem = publicKeyBase64
                .replaceAll("\\-*BEGIN.*KEY\\-*", "")
                .replaceAll("\\-*END.*KEY\\-*", "");
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(pem));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        System.out.println(publicKey);
        return publicKey;

    }

    /**
     * 获取PrivateKey对象
     * @param privateKeyBase64
     * @return
     */
    private PrivateKey getPrivateKey(String privateKeyBase64) {
        String privKeyPEM = privateKeyBase64
                .replaceAll("\\-*BEGIN.*KEY\\-*", "")
                .replaceAll("\\-*END.*KEY\\-*", "");

        // Base64 decode the data
        byte[] encoded = Base64.decodeBase64(privKeyPEM);

        try {
            DerInputStream derReader = new DerInputStream(encoded);
            DerValue[] seq = derReader.getSequence(0);

            if (seq.length < 9) {
                throw new GeneralSecurityException("Could not read private key");
            }

            // skip version seq[0];
            BigInteger modulus = seq[1].getBigInteger();
            BigInteger publicExp = seq[2].getBigInteger();
            BigInteger privateExp = seq[3].getBigInteger();
            BigInteger primeP = seq[4].getBigInteger();
            BigInteger primeQ = seq[5].getBigInteger();
            BigInteger expP = seq[6].getBigInteger();
            BigInteger expQ = seq[7].getBigInteger();
            BigInteger crtCoeff = seq[8].getBigInteger();

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp,
                    primeP, primeQ, expP, expQ, crtCoeff);

            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(keySpec);
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }
}