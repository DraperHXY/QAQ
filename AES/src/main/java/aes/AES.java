package aes;

import lombok.Data;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

@Data
public abstract class AES {
    private byte[] key;
    private byte[] iv;
    public static final int DEFAULT_SIZE = 16;


    public byte[] encrypt(byte[] plainBytes){
        // Make sure the validity of key, and plaintext
        assert (key != null && plainBytes != null);
        // The valid key length is 16Bytes, 24Bytes or 32Bytes
        assert (key.length == 16 || key.length == 24 || key.length == 32);

        try {
            BufferedBlockCipher b = encryptDetail();

            byte[] enc = new byte[b.getOutputSize(plainBytes.length)];
            int size1 = b.processBytes(plainBytes, 0, plainBytes.length, enc, 0);
            int size2;
            size2 = b.doFinal(enc, size1);
            byte[] ciphertext = new byte[size1 + size2];
            System.arraycopy(enc, 0, ciphertext, 0, ciphertext.length);
            return ciphertext;
        } catch (DataLengthException e) {
            e.printStackTrace();
            return null;
        } catch (IllegalStateException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            return null;
        }

    }

    public byte[] decrypt(byte[] cipherBytes){
        // Make sure the validity of key, and plaintext
        assert (key != null && cipherBytes != null);
        // The valid key length is 16Bytes, 24Bytes or 32Bytes
        assert (key.length == 16 || key.length == 24 || key.length == 32);

        BufferedBlockCipher b = decryptDetail();


        try {
            byte[] dec = new byte[b.getOutputSize(cipherBytes.length)];
            int size1 = b
                    .processBytes(cipherBytes, 0, cipherBytes.length, dec, 0);
            int size2 = b.doFinal(dec, size1);
            byte[] plaintext = new byte[size1 + size2];
            System.arraycopy(dec, 0, plaintext, 0, plaintext.length);
            return plaintext;
        } catch (DataLengthException e) {
            e.printStackTrace();
            return null;
        } catch (IllegalStateException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            return null;
        }
    }

    public abstract BufferedBlockCipher encryptDetail();

    public abstract BufferedBlockCipher decryptDetail();


    @Data
    public abstract static class Builder{
        private byte[] key = "6206c34e2186e752c74e6df32ab8fa5b".getBytes();
        private byte[] iv = "00e5d201c2c2acbff8154861242ba0c4".getBytes();

        public Builder withKey(byte[] key){
            this.key = key;
            return this;
        }

        public Builder withIv(byte[] iv){
            this.iv = iv;
            return this;
        }

        public abstract AES build();

    }

}
