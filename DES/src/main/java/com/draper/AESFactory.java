package com.draper;

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
import org.bouncycastle.util.encoders.Hex;

import java.io.*;

@Data
public class AESFactory {

    private String key;
    private String iv;
    private String iv_p;


    public static final byte[] InitVector = {0x38, 0x37, 0x36, 0x35, 0x34,
            0x33, 0x32, 0x31, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31};


    // The default block size in bits (note: a multiple of 8)
    private static int DEFAULT_SIZE = 16;

    public static byte[] enc_AES(Mode mode, byte[] key, byte[] iv,
                                 byte[] plaintext) {
        // Make sure the validity of key, and plaintext
        assert (key != null && plaintext != null);
        // The valid key length is 16Bytes, 24Bytes or 32Bytes
        assert (key.length == 16 || key.length == 24 || key.length == 32);
        if (mode != Mode.ECB) {
            // The valid encryptDetail vector is a no-none 16Bytes array
            assert (iv != null && iv.length == 16);
        }
        try {
            KeyParameter kp = new KeyParameter(key);
            BufferedBlockCipher b = null;
            switch (mode) {
                case ECB:
                    b = new PaddedBufferedBlockCipher(new AESEngine());
                    b.init(true, kp);
                    break;
                case CBC:
                    b = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                            new AESEngine()));
                    b.init(true, new ParametersWithIV(kp, iv));
                    break;
                case CFB:
                    b = new PaddedBufferedBlockCipher(new CFBBlockCipher(
                            new AESEngine(), DEFAULT_SIZE));
                    b.init(true, new ParametersWithIV(kp, iv));
                    break;
                case OFB:
                    b = new PaddedBufferedBlockCipher(new OFBBlockCipher(
                            new AESEngine(), DEFAULT_SIZE));
                    b.init(true, new ParametersWithIV(kp, iv));
                    break;
                default:
                    // Default Mode is ECB Mode
                    b = new PaddedBufferedBlockCipher(new AESEngine());
                    b.init(true, kp);
                    break;
            }
            byte[] enc = new byte[b.getOutputSize(plaintext.length)];
            int size1 = b.processBytes(plaintext, 0, plaintext.length, enc, 0);
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

    public static byte[] dec_AES(Mode mode, byte[] key, byte[] iv,
                                 byte[] ciphertext) {
        // Make sure the validity of key, and plaintext
        assert (key != null && ciphertext != null);
        // The valid key length is 16Bytes, 24Bytes or 32Bytes
        assert (key.length == 16 || key.length == 24 || key.length == 32);
        if (mode != Mode.ECB) {
            // The valid encryptDetail vector is a no-none 16Bytes array
            assert (iv != null && iv.length == 16);
        }
        try {
            KeyParameter kp = new KeyParameter(key);
            BufferedBlockCipher b = null;
            switch (mode) {
                case ECB:
                    b = new PaddedBufferedBlockCipher(new AESEngine());
                    b.init(false, kp);
                    break;
                case CBC:
                    b = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                            new AESEngine()));
                    b.init(false, new ParametersWithIV(kp, iv));
                    break;
                case CFB:
                    b = new PaddedBufferedBlockCipher(new CFBBlockCipher(
                            new AESEngine(), DEFAULT_SIZE));
                    b.init(false, new ParametersWithIV(kp, iv));
                    break;
                case OFB:
                    b = new PaddedBufferedBlockCipher(new OFBBlockCipher(
                            new AESEngine(), DEFAULT_SIZE));
                    b.init(false, new ParametersWithIV(kp, iv));
                    break;
                default:
                    // Default Mode is ECB Mode
                    b = new PaddedBufferedBlockCipher(new AESEngine());
                    b.init(false, kp);
                    break;
            }
            byte[] dec = new byte[b.getOutputSize(ciphertext.length)];
            int size1 = b
                    .processBytes(ciphertext, 0, ciphertext.length, dec, 0);
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

    public static void enc_AES(Mode mode, byte[] key, byte[] iv,
                               InputStream in, OutputStream out) {
        // Make sure the validity of key, and plaintext
        assert (key != null && in != null && out != null);
        // The valid key length is 16Bytes, 24Bytes or 32Bytes
        assert (key.length == 16 || key.length == 24 || key.length == 32);
        if (mode != Mode.ECB) {
            // The valid encryptDetail vector is a no-none 16Bytes array
            assert (iv != null && iv.length == 16);
        }
        try {
            KeyParameter kp = new KeyParameter(key);
            BufferedBlockCipher b = null;
            switch (mode) {
                case ECB:
                    b = new PaddedBufferedBlockCipher(new AESEngine());
                    b.init(true, kp);
                    break;
                case CBC:
                    b = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                            new AESEngine()));
                    b.init(true, new ParametersWithIV(kp, iv));
                    break;
                case CFB:
                    b = new PaddedBufferedBlockCipher(new CFBBlockCipher(
                            new AESEngine(), DEFAULT_SIZE));
                    b.init(true, new ParametersWithIV(kp, iv));
                    break;
                case OFB:
                    b = new PaddedBufferedBlockCipher(new OFBBlockCipher(
                            new AESEngine(), DEFAULT_SIZE));
                    b.init(true, new ParametersWithIV(kp, iv));
                    break;
                default:
                    // Default Mode is ECB Mode
                    b = new PaddedBufferedBlockCipher(new AESEngine());
                    b.init(true, kp);
                    break;
            }
            int inBlockSize = b.getBlockSize() * 10;
            int outBlockSize = b.getOutputSize(inBlockSize);
            byte[] inblock = new byte[inBlockSize];
            byte[] outblock = new byte[outBlockSize];

            int inL;
            int outL;
            byte[] rv = null;

            while ((inL = in.read(inblock, 0, inBlockSize)) > 0) {
                outL = b.processBytes(inblock, 0, inL, outblock, 0);

                if (outL > 0) {
                    rv = Hex.encode(outblock, 0, outL);

                    out.write(rv, 0, rv.length);
                    out.write('\n');
                }
            }

            outL = b.doFinal(outblock, 0);
            if (outL > 0) {
                rv = Hex.encode(outblock, 0, outL);
                out.write(rv, 0, rv.length);
                out.write('\n');
            }
        } catch (DataLengthException e) {
            e.printStackTrace();
            return;
        } catch (IllegalStateException e) {
            e.printStackTrace();
            return;
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            return;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void dec_AES(Mode mode, byte[] key, byte[] iv,
                               InputStream in, OutputStream out) {
        // Make sure the validity of key, and plaintext
        assert (key != null && in != null && out != null);
        // The valid key length is 16Bytes, 24Bytes or 32Bytes
        assert (key.length == 16 || key.length == 24 || key.length == 32);
        if (mode != Mode.ECB) {
            // The valid encryptDetail vector is a no-none 16Bytes array
            assert (iv != null && iv.length == 16);
        }
        try {
            KeyParameter kp = new KeyParameter(key);
            BufferedBlockCipher b = null;
            switch (mode) {
                case ECB:
                    b = new PaddedBufferedBlockCipher(new AESEngine());
                    b.init(false, kp);
                    break;
                case CBC:
                    b = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                            new AESEngine()));
                    b.init(false, new ParametersWithIV(kp, iv));
                    break;
                case CFB:
                    b = new PaddedBufferedBlockCipher(new CFBBlockCipher(
                            new AESEngine(), DEFAULT_SIZE));
                    b.init(false, new ParametersWithIV(kp, iv));
                    break;
                case OFB:
                    b = new PaddedBufferedBlockCipher(new OFBBlockCipher(
                            new AESEngine(), DEFAULT_SIZE));
                    b.init(false, new ParametersWithIV(kp, iv));
                    break;
                default:
                    // Default Mode is ECB Mode
                    b = new PaddedBufferedBlockCipher(new AESEngine());
                    b.init(false, kp);
                    break;
            }
            BufferedReader br = new BufferedReader(new InputStreamReader(in));

            byte[] inblock = null;
            byte[] outblock = null;

            int outL;
            String rv = null;

            while ((rv = br.readLine()) != null) {
                inblock = Hex.decode(rv);
                outblock = new byte[b.getOutputSize(inblock.length)];

                outL = b.processBytes(inblock, 0, inblock.length, outblock, 0);
                if (outL > 0) {
                    out.write(outblock, 0, outL);
                }
            }
            outL = b.doFinal(outblock, 0);
            if (outL > 0) {
                out.write(outblock, 0, outL);
            }
        } catch (DataLengthException e) {
            e.printStackTrace();
            return;
        } catch (IllegalStateException e) {
            e.printStackTrace();
            return;
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            return;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void Test_AES_String() {
        String key = "6206c34e2186e752c74e6df32ab8fa5b";
        String iv = "00e5d201c2c2acbff8154861242ba0c4";
        String iv_p = "00e5d201c2c2acbff8154861242ba0c5";
        String message;
        byte[] ciphertext, ciphertext_p;
        String plaintext, plaintext_p;


        // Test OFB Mode
        System.out.println("Test AESFactory with OFB Mode.");
        message = "明文消息";
        System.out.println("Message = " + message);
        // Test for Correctness
        ciphertext = enc_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv),
                message.getBytes());
        System.out.println("Encrypted Ciphertext = " + Hex.toHexString(ciphertext));
        plaintext = new String(dec_AES(Mode.OFB, Hex.decode(key),
                Hex.decode(iv), ciphertext));
        System.out.println("Decrypted Plaintext = " + plaintext);
        // Test for Encryption with distinct IV
        ciphertext_p = enc_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv_p),
                message.getBytes());
        System.out.println("Encrypted Ciphertext = "
                + Hex.toHexString(ciphertext_p));
        plaintext_p = new String(dec_AES(Mode.OFB, Hex.decode(key),
                Hex.decode(iv_p), ciphertext_p));
        System.out.println("Decrypted Plaintext = " + plaintext_p);
        System.out.println();
    }

    public byte[] encrypt(Mode mode, byte[] plainBytes) {
        switch (mode) {
            case ECB:
                return enECB(plainBytes, key);
            case CBC:
                return enCBC(plainBytes, key);
            case CFB:
                return enCFB(plainBytes, key);
            case OFB:
                return enOFB(plainBytes, key);
            default:
                return null;
        }
    }

    public byte[] decrypt(Mode mode, byte[] cipherBytes) {
        switch (mode) {
            case ECB:
                return deECB(cipherBytes, key);
            case CBC:
                return deCBC(cipherBytes, key);
            case CFB:
                return deCFB(cipherBytes, key);
            case OFB:
                return deOFB(cipherBytes, key);
            default:
                return null;
        }
    }

    public static void main(String[] args) {
        new AESFactory().Test_AES_String();

    }

    public static class Builder {

        private String key = "6206c34e2186e752c74e6df32ab8fa5b";
        private String iv = "00e5d201c2c2acbff8154861242ba0c4";
        private String ivP = "00e5d201c2c2acbff8154861242ba0c5";
        private String message;
        private byte[] ciphertext, ciphertext_p;
        private String plaintext, plaintext_p;

        public Builder withKey(String key) {
            this.key = key;
            return this;
        }

        public Builder withIv(String iv) {
            this.iv = iv;
            return this;
        }

        public Builder withIvP(String ivP) {
            this.ivP = ivP;
            return this;
        }

        public AESFactory build() {
            AESFactory factory = new AESFactory();
            factory.setKey(key);
            factory.setIv(iv);
            factory.setIv_p(ivP);
            return factory;
        }
    }

    /**
     * 采用 ECB mode 进行
     *
     * @param plainBytes 明文
     * @param key        秘钥
     */
    private byte[] enECB(byte[] plainBytes, String key) {
        byte[] cipherBytes = enc_AES(Mode.ECB, Hex.decode(key), null, plainBytes);
        return cipherBytes;
    }

    /**
     * 采用 ECB mode 进行
     *
     * @param cipherText 密文
     * @param key        秘钥
     */
    private byte[] deECB(byte[] cipherText, String key) {
        byte[] plainBytes = dec_AES(Mode.ECB, Hex.decode(key), null, cipherText);
        return plainBytes;
    }

    private byte[] enCBC(byte[] plainText, String key) {
        byte[] cipherBytes = enc_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv), plainText);
        return cipherBytes;
    }

    private byte[] deCBC(byte[] cipherText, String key) {
        byte[] plainBytes = dec_AES(Mode.CBC, Hex.decode(key), Hex.decode(iv), cipherText);
        return plainBytes;
    }

    private byte[] enCFB(byte[] plainBytes, String key) {
        byte[] cipherBytes = enc_AES(Mode.CFB, Hex.decode(key), Hex.decode(iv), plainBytes);
        return cipherBytes;
    }

    private byte[] deCFB(byte[] cipherBytes, String key) {
        byte[] plainBytes = dec_AES(Mode.CFB, Hex.decode(key), Hex.decode(iv), cipherBytes);
        return plainBytes;
    }

    private byte[] enOFB(byte[] plainBytes, String key) {
        byte[] cipherBytes = enc_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv), plainBytes);
        return cipherBytes;
    }

    private byte[] deOFB(byte[] cipherBytes, String key) {
        byte[] plainBytes = dec_AES(Mode.OFB, Hex.decode(key), Hex.decode(iv), cipherBytes);
        return plainBytes;
    }


    public enum Mode {
        /**
         * Electronic CodeBook Mode
         */
        ECB,

        /**
         * Cipher-Block Chaining Mode
         */
        CBC,

        /**
         * Cipher FeedBack Mode
         */

        CFB,
        /**
         * Output FeedBack Mode
         */
        OFB,
    }


}