import aes.*;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class EcbAESTest {

    @Test
    public void test() {
        EcbAES ecbAES = (EcbAES) new EcbAES.Builder().withKey("6206c34e2186e752c74e6df32ab8fa5b".getBytes()).build();
        byte[] cipherBytes = ecbAES.encrypt("Hello World".getBytes());
        byte[] plainBytes = ecbAES.decrypt(cipherBytes);
        System.out.println(new String(plainBytes));
    }

    @Test
    public void test1() {
        EcbAES ecbAES = (EcbAES) new EcbAES.Builder().build();
        byte[] cipherBytes = ecbAES.encrypt("你好 佳能".getBytes());
        byte[] plainText = ecbAES.decrypt(cipherBytes);
        System.out.println(new String(plainText));
    }

    @Test
    public void test2() throws Exception {
        CbcAES cbcAES = (CbcAES) new CbcAES.Builder()
                .build();
        byte[] cipherBytes = cbcAES.encrypt("Hello World".getBytes());
        byte[] plainBytes = cbcAES.decrypt(cipherBytes);
        System.out.println(new String(plainBytes));
    }

    @Test
    public void testIv() throws Exception {
        System.out.println(Hex.decode("00e5d201c2c2acbff8154861242ba0c4").length);
    }

    @Test
    public void test3() throws Exception{
        CfbAES cfbAES = (CfbAES) new CfbAES.Builder().build();
        byte[] cipherBytes = cfbAES.encrypt("Hello Worldddd".getBytes());
        byte[] plainBytes = cfbAES.decrypt(cipherBytes);
        System.out.println(new String(plainBytes));
    }

    @Test
    public void test4() throws Exception{
        OfbAES ofbAES = (OfbAES) new OfbAES.Builder().build();
        byte[] cipherBytes = ofbAES.encrypt("Hello Worldddd".getBytes());
        byte[] plainBytes = ofbAES.decrypt(cipherBytes);
        System.out.println(new String(plainBytes));

    }
}
