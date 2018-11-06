package com.draper;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import static com.draper.AESFactory.enc_AES;
import static com.draper.AESFactory.dec_AES;

public class AESFactoryTest {
    private String plainText;

    @Before
    public void beforeTest() {
        plainText = "传输内容：account = [" + "admin" + "],password = [" + "admin" + "]";
    }

    @Test
    public void testECBencrypt() {
        String plainText = "传输内容：********￥%￥……￥%……";
        AESFactory factory = new AESFactory.Builder().build();
        byte[] cipherBytes = factory.encrypt(AESFactory.Mode.ECB, plainText.getBytes());
        String cipherText = new String(cipherBytes);
        System.out.println(cipherText);
    }

    @Test
    public void testECBdecrypt() {
        String cryptHexText = "48628fb0bf1fe4c62d86458b2165deb2c84a911db115e800f174055060b204049f463606f9aa9fe719bd6a3b3922e3e3";
        AESFactory factory = new AESFactory.Builder().build();
        byte[] plainBytes = factory.decrypt(AESFactory.Mode.ECB, Hex.decode(cryptHexText));
        String plainText = new String(plainBytes);
        System.out.println(plainText);
    }

    @Test
    public void testECB() {
        String plainText = "传输内容：********￥%￥……￥%……";
        AESFactory factory = new AESFactory.Builder().build();
        byte[] cipherBytes = factory.encrypt(AESFactory.Mode.ECB, plainText.getBytes());
        String cipherText = Hex.toHexString(cipherBytes);
        System.out.println(cipherText);
        cipherBytes = Hex.decode(cipherText);
        byte[] plainBytes = factory.decrypt(AESFactory.Mode.ECB, cipherBytes);
        plainText = new String(plainBytes);
        System.out.println(plainText);
    }

    @Test
    public void testECB2() {
        AESFactory factory = new AESFactory.Builder().build();

        // Test ECB Mode
        String key = "6206c34e2186e752c74e6df32ab8fa5b";

        System.out.println("Test AESFactory with ECB Mode.");
        String message = "明文消息";
        System.out.println("Message = " + message);
        byte[] cipherBytes = factory.encrypt(AESFactory.Mode.ECB, message.getBytes());
//        enc_AES(AESFactory.Mode.ECB, Hex.decode(key), null, message.getBytes());
//        System.out.println("Encrypted Ciphertext = " + Hex.toHexString(cipherBytes));
//        plaintext = new String(dec_AES(Mode.ECB, Hex.decode(key), null,
//                cipherBytes));
        String plaintext = new String(factory.decrypt(AESFactory.Mode.ECB, cipherBytes));
//        String plaintext = new String(dec_AES(AESFactory.Mode.ECB, Hex.decode(key), null, cipherBytes));
        System.out.println("Decrypted Plaintext = " + plaintext);
        System.out.println();
    }

    @Test
    public void testCBC() {
        AESFactory factory = new AESFactory.Builder().build();
        byte[] cipherBytes = factory.encrypt(AESFactory.Mode.CBC, plainText.getBytes());
        byte[] plainBytes = factory.decrypt(AESFactory.Mode.CBC, cipherBytes);
        System.out.println(new String(plainBytes));
    }

    @Test
    public void testCFB() {
        AESFactory factory = new AESFactory.Builder().build();
        byte[] cipherBytes = factory.encrypt(AESFactory.Mode.CFB, plainText.getBytes());
        byte[] plainBytes = factory.decrypt(AESFactory.Mode.CFB, cipherBytes);
        System.out.println(new String(plainBytes));
    }

    @Test
    public void testOFB() {
        AESFactory factory = new AESFactory.Builder().build();
        byte[] cipherBytes = factory.encrypt(AESFactory.Mode.OFB, plainText.getBytes());
        byte[] plainBytes = factory.decrypt(AESFactory.Mode.OFB, cipherBytes);
        System.out.println(new String(plainBytes));
    }
}
