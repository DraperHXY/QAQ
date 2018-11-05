package aes;

import lombok.Data;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class EcbAES extends AES {

    private EcbAES() {
    }

    public BufferedBlockCipher encryptDetail() {
        KeyParameter kp = new KeyParameter(super.getKey());
        BufferedBlockCipher b = null;
        b = new PaddedBufferedBlockCipher(new AESEngine());
        b.init(true, kp);
        return b;
    }

    public BufferedBlockCipher decryptDetail() {
        KeyParameter kp = new KeyParameter(super.getKey());
        BufferedBlockCipher b = null;
        b = new PaddedBufferedBlockCipher(new AESEngine());
        b.init(false, kp);
        return b;
    }

    public static class Builder extends AES.Builder {

        @Override
        public AES.Builder withIv(byte[] iv) {
            return super.withIv(null);
        }

        public EcbAES build() {
            EcbAES aes = new EcbAES();
            //把 Builder 中的 key 交到 AES 手中
            aes.setKey(super.getKey());
            return aes;
        }

    }

    public byte[] encrypt(byte[] plainText) {
        return super.encrypt(plainText);
    }


    public byte[] decrypt(byte[] cipherText) {
        return super.decrypt(cipherText);
    }
}
