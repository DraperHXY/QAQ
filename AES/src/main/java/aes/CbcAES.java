package aes;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class CbcAES extends AES {

    private CbcAES() {
    }

    public BufferedBlockCipher encryptDetail() {
        KeyParameter kp = new KeyParameter(super.getKey());
        BufferedBlockCipher b = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                new AESEngine()));
        b.init(true, new ParametersWithIV(kp, super.getIv()));
        return b;
    }

    public BufferedBlockCipher decryptDetail() {
        KeyParameter kp = new KeyParameter(super.getKey());
        BufferedBlockCipher b = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                new AESEngine()));
        b.init(false, new ParametersWithIV(kp, super.getIv()));
        return b;
    }

    public static class Builder extends AES.Builder {

        public AES build() {
            CbcAES aes = new CbcAES();
            aes.setKey(super.getKey());
            //将 iv 编码成 16 位
            aes.setIv(Hex.decode(super.getIv()));
            return aes;
        }
    }
}
