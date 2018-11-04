package com.draper;

import org.junit.Test;

public class DESFactoryTest {

    @Test
    public void testEncryet(){
        byte[] encrypt = new DESFactory.Builder().encrypt("Hello".getBytes());
        System.out.println(new String(encrypt));
        byte[] decrypt = new DESFactory.Builder().decrypt(encrypt);
        System.out.println(new String(decrypt));
    }

}
