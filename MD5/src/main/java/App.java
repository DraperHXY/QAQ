import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.util.encoders.Hex;

public class App {

    public static void main(String[] args) {
        String plainText = "dddd";
        MD5Digest md5Digest = new MD5Digest();
        byte[] cipherBytes = new byte[md5Digest.getDigestSize()];
        md5Digest.doFinal(cipherBytes, 0);
        md5Digest.update(plainText.getBytes(), 0, plainText.getBytes().length);
        String cipherText = Hex.toHexString(cipherBytes);
        System.out.println(cipherText);
    }
    //d41d8cd98f00b204e9800998ecf8427e
    //d41d8cd98f00b204e9800998ecf8427e

}
