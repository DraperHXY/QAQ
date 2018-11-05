package aes;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class CfbAES extends AES {

    public BufferedBlockCipher encryptDetail() {
        KeyParameter kp = new KeyParameter(super.getKey());
        BufferedBlockCipher b = new PaddedBufferedBlockCipher(new CFBBlockCipher(
                new AESEngine(), super.DEFAULT_SIZE));
        b.init(true, new ParametersWithIV(kp, super.getIv()));
        return b;
    }

    public BufferedBlockCipher decryptDetail() {
        KeyParameter kp = new KeyParameter(super.getKey());
        BufferedBlockCipher b = new PaddedBufferedBlockCipher(new CFBBlockCipher(
                new AESEngine(), super.DEFAULT_SIZE));
        b.init(false, new ParametersWithIV(kp, super.getIv()));
        return b;
    }

    public static class Builder extends AES.Builder {

        public AES build() {
            CfbAES aes = new CfbAES();
            aes.setKey(Hex.decode(super.getKey()));
            aes.setIv(Hex.decode(super.getIv()));
            return aes;
        }
    }
}
