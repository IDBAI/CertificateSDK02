package com.revenco.certificatesdk;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import com.revenco.certificateverifylib.core.ECDSAHelper;
import com.revenco.ecdsalibrary.common.Utils;
import com.revenco.ecdsalibrary.core.ECDSA;

import java.io.File;
import java.io.IOException;
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

public class MainActivity extends Activity implements View.OnClickListener {
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
    private static final int SIGNVERIFYTESTLOOP = 1000;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private KeyPair ecdsaKeyPair;
    private byte[] sign;
    private EditText editTextLog;

    private void debug(String TAG, final String string) {
        Log.d(TAG, string);
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                editTextLog.append(string + "\n");
            }
        });
    }

    private void error(String TAG, final String string) {
        Log.e(TAG, string);
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                editTextLog.append(string + "\n");
            }
        });
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.baseTest).setOnClickListener(this);
        findViewById(R.id.signChangeTest).setOnClickListener(this);
        findViewById(R.id.contentChangeTest).setOnClickListener(this);
        findViewById(R.id.multSignMultVerify).setOnClickListener(this);
        findViewById(R.id.clearLog).setOnClickListener(this);
        editTextLog = (EditText) findViewById(R.id.logshow);
    }

    /**
     * 生成key
     *
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    public void generationKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        //
        ecdsaKeyPair = ECDSA.getECDSAKeyPair();
        if (ecdsaKeyPair != null) {
            debug(TAG, "ecdsaKeyPair != null");
        }
        privateKey = ECDSA.getPrivatekey(ecdsaKeyPair);
        publicKey = ECDSA.getPublickey(ecdsaKeyPair);
        if (privateKey != null) {
            debug(TAG, "privateKey != null");
        }
        if (publicKey != null) {
            debug(TAG, "publicKey != null");
        }
        // key的算法和format必须符合相关的约束
        if (privateKey.getFormat().equalsIgnoreCase("PKCS#8")) {
            debug(TAG, "私钥格式符合PKCS#8");
        }
        if (publicKey.getFormat().equalsIgnoreCase("X.509")) {
            debug(TAG, "共钥格式符合X.509");
        }
        if (privateKey.getAlgorithm().equalsIgnoreCase("ECC")) {
            debug(TAG, "私钥算法符合ECC");
        }
        if (publicKey.getAlgorithm().equalsIgnoreCase("ECC")) {
            debug(TAG, "公钥算法符合ECC");
        }
        if (ECDSA.isECDSAKeyPair(publicKey, privateKey)) {
            debug(TAG, "公钥私钥匹配！");
        }
    }

    private void writeKeyToSDcard() throws IOException {
        if (publicKey == null) {
            debug(TAG, "公钥为空");
            return;
        }
        if (privateKey == null) {
            debug(TAG, "私钥为空");
            return;
        }
        //将公钥写入SDcard
        File publicFile = StorageUtils.getDataPath(MainActivity.this, publicKeyFilePath);
        ECDSAHelper.writePublicKeyToPem(publicKey, publicFile.getAbsolutePath());
        //将私钥写入SDcard
        File privateFile = StorageUtils.getDataPath(MainActivity.this, privateKeyFilePath);
        ECDSAHelper.writePrivateKeyToPem(privateKey, privateFile.getAbsolutePath());
        debug(TAG, "写入公、密钥到SDCard成功");
    }

    private void loadKeyFromSdCard() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        //
        File publicFile = StorageUtils.getDataPath(MainActivity.this, publicKeyFilePath);
        publicKey = ECDSAHelper.loadPublicKeyFromPem(publicFile.getAbsolutePath());
        //
        File privateFile = StorageUtils.getDataPath(MainActivity.this, privateKeyFilePath);
        privateKey = ECDSAHelper.loadPrivateKeyFromPem(privateFile.getAbsolutePath());
        debug(TAG, "从Sdcard加载公、密钥成功");
    }

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
        debug(TAG, "校验结果：" + verifySign);
    }

    /**
     * 测试同一数据多次签名多次校验的情况
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private void signVerifymult() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        for (int i = 0; i < 100; i++) {
            byte[] testdata = new byte[]{(byte) i};
            byte[] pre_sign = new byte[1];
            for (int j = 0; j < 100; j++) {
                byte[] sign = ECDSA.generateSign(privateKey, testdata);
                boolean verifySign = ECDSA.verifySign(publicKey, testdata, sign);
                boolean equals = Arrays.equals(pre_sign, sign);
                if (!verifySign)
                    error(TAG, "[" + i + " , " + j + "]" + " ：校验是否成功：" + verifySign);
                else
                    debug(TAG, "[" + i + " , " + j + "]" + " ：校验是否成功：" + verifySign);
                if (equals)
                    error(TAG, "[" + i + " , " + j + "]" + " ：签名是否相同：" + equals);
                else
                    debug(TAG, "[" + i + " , " + j + "]" + " ：签名是否相同：" + equals);
                pre_sign = sign;
            }
        }
    }

    /**
     * 随机修改xx次原数据，必须返回false
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private void signVerifyModifyContextTest() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] testdata = new byte[20];
        for (int i = 0; i < 10; i++) {
            testdata[i] = (byte) Math.round(10.0f);
        }
        debug(TAG, "testdata:" + Utils.byte2HexStrWithoutSpace(testdata));
        byte[] sign = ECDSA.generateSign(privateKey, testdata);
        boolean verifySign = ECDSA.verifySign(publicKey, testdata, sign);
        debug(TAG, "校验是否成功：" + verifySign);
        debug(TAG, "开始修改原始数据" + SIGNVERIFYTESTLOOP + "次,判断校验是否成功");
        for (int j = 0; j < SIGNVERIFYTESTLOOP; j++) {
            int round = Math.round(10.0f);
            testdata[round] = (byte) round;
            debug(TAG, "testdata:" + Utils.byte2HexStrWithoutSpace(testdata));
            verifySign = ECDSA.verifySign(publicKey, testdata, sign);
            if (verifySign)
                debug(TAG, "[" + j + "]" + " ：校验是否成功：" + verifySign);
            else
                error(TAG, "[" + j + "]" + " ：校验是否成功：" + verifySign);
        }
    }

    /**
     * 测试签名被篡改的情况下，测试
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private void signVerifyModifySignatureTest() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] testdata = new byte[10];
        for (int i = 0; i < 10; i++) {
            testdata[i] = (byte) Math.round(10.0f);
        }
        debug(TAG, "testdata:" + Utils.byte2HexStrWithoutSpace(testdata));
        byte[] sign = ECDSA.generateSign(privateKey, testdata);
        boolean verifySign = ECDSA.verifySign(publicKey, testdata, sign);
        debug(TAG, "校验是否成功：" + verifySign);
        debug(TAG, "开始修改签名" + SIGNVERIFYTESTLOOP + "次,判断校验是否成功");
        for (int j = 0; j < SIGNVERIFYTESTLOOP; j++) {
            int round = Math.round(10.0f);
            sign[round] = (byte) round;
            verifySign = ECDSA.verifySign(publicKey, testdata, sign);
            if (verifySign)
                debug(TAG, "[" + j + "]" + " ：校验是否成功：" + verifySign);
            else
                error(TAG, "[" + j + "]" + " ：校验是否成功：" + verifySign);
        }
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.baseTest:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        baseTest();
                    }
                }).start();
                break;
            case R.id.signChangeTest:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                    }
                }).start();
                signChangeTest();
                break;
            case R.id.contentChangeTest:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        contentChangeTest();
                    }
                }).start();
                break;
            case R.id.multSignMultVerify:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        multSignMultVerify();
                    }
                }).start();
                break;
            case R.id.clearLog:
                editTextLog.setText("");
                break;
        }
    }

    private void multSignMultVerify() {
        try {
            signVerifymult();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    private void baseTest() {
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
            writeKeyToSDcard();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            loadKeyFromSdCard();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
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

    private void signChangeTest() {
        try {
            signVerifyModifySignatureTest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    private void contentChangeTest() {
        try {
            signVerifyModifyContextTest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }
}
