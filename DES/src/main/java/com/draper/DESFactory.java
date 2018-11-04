package com.draper;

import java.util.HashMap;
import java.util.Map;

public class DESFactory {


    private DESFactory() {

    }
//    static factory(){dffd
//        Map<String, String> map = new HashMap<String, String>();
//        return name -> map.get(name).get;
//    }

    public static class Builder {
        //密码，长度要是8的倍数
        private String password = "9588028820109132570743325311898426347857298773549468758875018579537757772163084478873699447306034466200616411960574122434059469100235892702736860872901247123456";

        public Builder() {
        }

        public Builder withPassword(String password) {
            this.password = password;
            return this;
        }

        public byte[] encrypt(byte[] decryet) {
            try {
                return DES.encrypt(decryet, password);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        public byte[] decrypt(byte[] encrypt) {
            try {
                return DES.decrypt(encrypt,password);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }


    }


}
