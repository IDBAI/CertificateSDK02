package com.revenco.certificatesdk;

import android.widget.EditText;

import com.revenco.ecdsalibrary.common.Utils;
import com.revenco.ecdsalibrary.core.ECDSA;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * <p>PROJECT : CertificateSDK</p>
 * <p>COMPANY : wanzhong</p>
 * <p>AUTHOR : Administrator on 2017/3/13 17:46.</p>
 * <p>CLASS DESCRIBE :仅仅用于测试的类</p>
 * <p>CLASS_VERSION : 1.0.0</p>
 */
public class ECDSATest {
    private static final String TAG = "MainActivity";
    private static final String publicKeyFilePath = "Certificate/publicKey.pem";
    private static final String privateKeyFilePath = "Certificate/privateKey.pem";
    private static final byte[] testData = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
    };
    /**
     *
     */
    private static final int SIGNVERIFYTESTLOOP = 100000;
    private static ECDSATest instance = new ECDSATest();
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private KeyPair ecdsaKeyPair;
    private byte[] sign;
    private EditText editTextLog;

    public static ECDSATest getIntance() {
        return instance;
    }

    private void debug(String TAG, final String string) {
        System.out.println(string);
    }

    /**
     * 生成key
     *
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    private void generationKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        //
        ecdsaKeyPair = ECDSA.getECDSAKeyPair();
        if (ecdsaKeyPair == null) {
            debug(TAG, "ecdsaKeyPair 为空");
            return;
        }
        privateKey = ECDSA.getPrivatekey(ecdsaKeyPair);
        publicKey = ECDSA.getPublickey(ecdsaKeyPair);
        if (privateKey == null) {
            debug(TAG, "privateKey 为空");
            return;
        }
        if (publicKey == null) {
            debug(TAG, "publicKey 为空");
            return;
        }
        // key的算法和format必须符合相关的约束
        if (!privateKey.getFormat().equalsIgnoreCase("PKCS#8")) {
            debug(TAG, "私钥格式不符合PKCS#8");
            return;
        }
        if (!publicKey.getFormat().equalsIgnoreCase("X.509")) {
            debug(TAG, "共钥格式不符合X.509");
            return;
        }
        if (!privateKey.getAlgorithm().equalsIgnoreCase("ECDSA")) {
            debug(TAG, "私钥算法不符合ECDSA");
            return;
        }
        if (!publicKey.getAlgorithm().equalsIgnoreCase("ECDSA")) {
            debug(TAG, "公钥算法不符合ECDSA");
            return;
        }
        if (!ECDSA.isECDSAKeyPair(publicKey, privateKey)) {
            debug(TAG, "公钥私钥不匹配！");
            return;
        }
    }
//    private void writeKeyToSDcard() throws IOException {
//        if (publicKey == null) {
//            debug(TAG, "公钥为空");
//            return;
//        }
//        if (privateKey == null) {
//            debug(TAG, "私钥为空");
//            return;
//        }
//        //将公钥写入SDcard
//        File publicFile = StorageUtils.getDataPath(MainActivity.this, publicKeyFilePath);
//        ECDSAHelper.writePublicKeyToPem(publicKey, publicFile.getAbsolutePath());
//        //将私钥写入SDcard
//        File privateFile = StorageUtils.getDataPath(MainActivity.this, privateKeyFilePath);
//        ECDSAHelper.writePrivateKeyToPem(privateKey, privateFile.getAbsolutePath());
//        debug(TAG, "写入公、密钥到SDCard成功");
//    }
//    private void loadKeyFromSdCard() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
//        //
//        File publicFile = StorageUtils.getDataPath(MainActivity.this, publicKeyFilePath);
//        publicKey = ECDSAHelper.loadPublicKeyFromPem(publicFile.getAbsolutePath());
//        //
//        File privateFile = StorageUtils.getDataPath(MainActivity.this, privateKeyFilePath);
//        privateKey = ECDSAHelper.loadPrivateKeyFromPem(privateFile.getAbsolutePath());
//        debug(TAG, "从Sdcard加载公、密钥成功");
//    }

    private void genarationSign() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (privateKey == null) {
            debug(TAG, "私钥为空！");
            return;
        }
        sign = ECDSA.generateSign(privateKey, testData);
    }

    private void verifySign() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (publicKey == null) {
            debug(TAG, "公钥为空");
            return;
        }
        if (sign == null) {
            debug(TAG, "签名为空，请先生成签名！");
            return;
        }
        boolean verifySign = ECDSA.verifySign(publicKey, testData, sign);
        if (!verifySign)
            debug(TAG, "校验失败！");
    }

    /**
     * 测试同一数据多次签名多次校验的情况
     *
     * @param outloop
     * @param inloop
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private void signVerifymult(int outloop, int inloop) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        int size = 150;
        for (int i = 0; i < outloop; i++) {
            byte[] testdata = new byte[size];
            for (int j = 0; j < size; j++) {
                int va = (byte) (Math.random() * 10);
                testdata[j] = (byte) va;
            }
            byte[] pre_sign = new byte[1];
            for (int j = 0; j < inloop; j++) {
                byte[] sign = ECDSA.generateSign(privateKey, testdata);
                boolean verifySign = ECDSA.verifySign(publicKey, testdata, sign);
                boolean equals = Arrays.equals(pre_sign, sign);
//                debug(TAG, "[" + i + " , " + j + "]" + " ：校验是否成功：" + verifySign);
//                debug(TAG, "[" + i + " , " + j + "]" + " ：签名是否相同：" + equals);
                pre_sign = sign;
                if (!verifySign) {
                    //记录下异常数据
                    debug(TAG, "异常--签名校验不成功！");
                    String strpublicKey = Utils.byte2HexStrWithoutSpace(publicKey.getEncoded());
                    String strData = Utils.byte2HexStrWithoutSpace(testdata);
                    String strsign = Utils.byte2HexStrWithoutSpace(sign);
                    debug(TAG, "strData : " + strData);
                    debug(TAG, "strsign : " + strsign);
                    debug(TAG, "strpublicKey : " + strpublicKey);
                }
                if (equals) {
                    //记录下异常数据
                    debug(TAG, "异常--两次签名相等");
                    String strpublicKey = Utils.byte2HexStrWithoutSpace(publicKey.getEncoded());
                    String strData = Utils.byte2HexStrWithoutSpace(testdata);
                    String strsign = Utils.byte2HexStrWithoutSpace(sign);
                    debug(TAG, "strData : " + strData);
                    debug(TAG, "strsign : " + strsign);
                    debug(TAG, "strpublicKey : " + strpublicKey);
                }
            }
        }
    }

    /**
     * 随机修改xx次原数据，必须返回false
     *
     * @param loop
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private void signVerifyModifyContextTest(int loop) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        int size = 50;
        byte[] testdata = new byte[size];
        for (int i = 0; i < size; i++) {
            testdata[i] = (byte) (Math.random() * size);
        }
//        debug(TAG, "testdata:" + Utils.byte2HexStrWithoutSpace(testdata));
        byte[] sign = ECDSA.generateSign(privateKey, testdata);
        boolean verifySign = ECDSA.verifySign(publicKey, testdata, sign);
        debug(TAG, "校验是否成功：" + verifySign);
        debug(TAG, "开始修改原始数据" + loop + "次,判断校验是否成功");
        for (int j = 0; j < loop; j++) {
            int time = (int) (Math.random() * (20));//  随机修改次数
            for (int i = 0; i < time; i++) {
                int random = (int) (Math.random() * (size - 2));// 随机修改位置
                testdata[random] = (byte) random;
                testdata[random + 1] = (byte) random;
                testdata[random + 2] = (byte) random;
            }
//            debug(TAG, "testdata:" + Utils.byte2HexStrWithoutSpace(testdata));
            boolean verifySign1 = false;
            try {
                verifySign1 = ECDSA.verifySign(publicKey, testdata, sign);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            }
//            debug(TAG, "[" + j + "]" + " ：校验是否成功：" + verifySign1);
            if (verifySign1) {
                //记录下异常数据
                debug(TAG, "有记录下异常数据");
                String strpublicKey = Utils.byte2HexStrWithoutSpace(publicKey.getEncoded());
                String strData = Utils.byte2HexStrWithoutSpace(testdata);
                String strsign = Utils.byte2HexStrWithoutSpace(sign);
                debug(TAG, "strData : " + strData);
                debug(TAG, "strsign : " + strsign);
                debug(TAG, "strpublicKey : " + strpublicKey);
            }
        }
    }

    /**
     * 测试签名被篡改的情况下，测试
     *
     * @param loop
     * @param isExcludePrePosition 是否要排除前5字节的随机位
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private void signVerifyModifySignatureTest(int loop, boolean isExcludePrePosition) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        int size = 150;
        byte[] testdata = new byte[size];
        for (int i = 0; i < size; i++) {
            testdata[i] = (byte) (Math.random() * 10);
        }
        debug(TAG, "testdata:" + Utils.byte2HexStrWithoutSpace(testdata));
        byte[] sign = ECDSA.generateSign(privateKey, testdata);
        boolean verifySign = ECDSA.verifySign(publicKey, testdata, sign);
        debug(TAG, "校验是否成功：" + verifySign);
        debug(TAG, "开始修改签名" + loop + "次,判断校验是否成功");
        for (int j = 0; j < loop; j++) {
            int random = (byte) (Math.random() * 50);
//            修改前五个字节，需要抛出无效格式/签名异常
//            随机修改第6个后面的字节，需要返回false！
            if (isExcludePrePosition) {//避免修改前5字节
                random = random - 6;
                random = random < 6 ? 6 : random;
            }
            sign[random] = (byte) random;
            boolean verifySign1 = false;
            try {
                verifySign1 = ECDSA.verifySign(publicKey, testdata, sign);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                //修改前五个字节，需要抛出无效格式/签名异常
//                e.printStackTrace();
                debug(TAG, "SignatureException");
                debug(TAG, "random = " + random);
            }
//            debug(TAG, "[" + j + "]" + " ：校验是否成功：" + verifySign1);
            if (verifySign1) {
                //记录下异常数据
                debug(TAG, "有记录下异常数据");
                String strpublicKey = Utils.byte2HexStrWithoutSpace(publicKey.getEncoded());
                String strData = Utils.byte2HexStrWithoutSpace(testdata);
                String strsign = Utils.byte2HexStrWithoutSpace(sign);
                debug(TAG, "strData : " + strData);
                debug(TAG, "strsign : " + strsign);
                debug(TAG, "strpublicKey : " + strpublicKey);
            }
        }
    }

    public void multSignMultVerify(int outloop, int inloop) {
        try {
            signVerifymult(outloop, inloop);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    public void baseTest() {
        try {
            generationKey();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        try {
            genarationSign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        try {
            verifySign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    public void signChangeTest(int loop, boolean isExcludePrePosition) {
        try {
            signVerifyModifySignatureTest(loop, isExcludePrePosition);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    public void contentChangeTest(int loop) {
        try {
            signVerifyModifyContextTest(loop);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }
}
