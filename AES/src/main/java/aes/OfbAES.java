package aes;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class OfbAES extends AES {

    private OfbAES() {
    }

    public BufferedBlockCipher encryptDetail() {
        KeyParameter kp = new KeyParameter(super.getKey());
        BufferedBlockCipher b = new PaddedBufferedBlockCipher(new OFBBlockCipher(
                new AESEngine(), DEFAULT_SIZE));
        b.init(true, new ParametersWithIV(kp, super.getIv()));
        return b;
    }

    public BufferedBlockCipher decryptDetail() {
        KeyParameter kp = new KeyParameter(super.getKey());
        BufferedBlockCipher b = new PaddedBufferedBlockCipher(new OFBBlockCipher(
                new AESEngine(), super.DEFAULT_SIZE));
        b.init(false, new ParametersWithIV(kp, super.getIv()));
        return b;
    }

    public static class Builder extends AES.Builder {

        public AES build() {
            OfbAES aes = new OfbAES();
            aes.setKey(super.getKey());
            aes.setIv(Hex.decode(super.getIv()));
            return aes;
        }
    }

}
