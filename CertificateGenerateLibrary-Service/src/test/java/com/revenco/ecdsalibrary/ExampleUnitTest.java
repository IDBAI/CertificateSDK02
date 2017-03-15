package com.revenco.ecdsalibrary;

import com.revenco.ecdsalibrary.common.Utils;
import com.revenco.ecdsalibrary.core.Cerfiticate;
import com.revenco.ecdsalibrary.core.ECDSA;

import org.junit.Test;
import org.spongycastle.util.encoders.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.GregorianCalendar;

import static org.junit.Assert.assertEquals;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    @Test
    public void addition_isCorrect() throws Exception {
        assertEquals(4, 2 + 2);
    }

    @Test
    public void testECDSAJar() {
        //1、生成证书原始数据
        byte[] userId = new byte[16];
        for (int i = 0; i < 16; i++) {
            userId[i] = (byte) ((byte) i + 16);
        }
        byte[] BleMac = new byte[]{0x4A, (byte) 0xD2, (byte) 0xF1, 0x30, (byte) 0xC5, (byte) 0x8E};//mi2s ble mac
        byte[] deviceId = new byte[16];
        for (int i = 0; i < 16; i++) {
            deviceId[i] = (byte) i;
        }
        byte[] channelMask = new byte[]{0x00};
        //签发时间
        Date currentData = new Date();
//        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:sss");
//        System.out.println("currentData：" + format.format(currentData));
        long time = currentData.getTime();
        byte[] issueTime = Utils.intToByteArray((int) time);//当前签发证书时间 0000015A 4B1432B4 ,强转int，即相当于在不超过INT_MAX情况下，直接砍掉高位以节省数据量
        //失效时间
        GregorianCalendar calendar = new GregorianCalendar();
        calendar.setTime(currentData);
        calendar.add(calendar.DATE, 1);//往后推一天,表示证书有效期1天,这个可以设定
        Date tomorrow = calendar.getTime();
//        System.out.println("tomorrow：" + format.format(tomorrow));
        long tomorrowTime = tomorrow.getTime();
        byte[] timeout = Utils.intToByteArray((int) tomorrowTime);//直接砍掉高位以节省数据量
        byte[] counter = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte[] useTimes = new byte[]{0x05};
        byte[] certificateOriginal = new byte[0];
        try {
            certificateOriginal = Cerfiticate.genCertifiOriginalV2(Cerfiticate.TYPE.FIX_ADDR_ECDSA_SHA256, userId, BleMac, deviceId, channelMask, issueTime, timeout, counter, useTimes);
//            certificateOriginal = Cerfiticate.generateCertificateOriginal(type, userId, BleMac, deviceId, channelMask, issueTime, timeout, counter, useTimes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("userId：" + Utils.byte2HexStrWithoutSpace(userId));
        System.out.println("BleMac：" + Utils.byte2HexStrWithoutSpace(BleMac));
        System.out.println("deviceId：" + Utils.byte2HexStrWithoutSpace(deviceId));
        System.out.println("channelMask：" + Utils.byte2HexStrWithoutSpace(channelMask));
        System.out.println("issueTime：" + Utils.byte2HexStrWithoutSpace(issueTime));
        System.out.println("timeout：" + Utils.byte2HexStrWithoutSpace(timeout));
        System.out.println("counter：" + Utils.byte2HexStrWithoutSpace(counter));
        System.out.println("useTimes：" + Utils.byte2HexStrWithoutSpace(useTimes));
        String hexStrWithoutSpace = Utils.byte2HexStrWithoutSpace(certificateOriginal);
        System.out.println("证书拼接的原始数据：" + hexStrWithoutSpace + " ,长度：" + certificateOriginal.length + " 字节");
        //2、生成私钥(获得)
        KeyPair ecdsaKeyPair;
        PrivateKey privatekey = null;
        try {
            ecdsaKeyPair = ECDSA.getECDSAKeyPair();
            privatekey = ECDSA.getPrivatekey(ecdsaKeyPair);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        String privatekeystr = Utils.byte2HexStrWithoutSpace(privatekey.getEncoded());
        System.out.println("私钥数据长度：" + privatekeystr.length() / 2 + " 字节");
        //3、根据私钥生成签名
        byte[] sign = new byte[0];
        try {
            sign = Cerfiticate.generateCertificateSign(privatekey, certificateOriginal);
        } catch (Exception e) {
            e.printStackTrace();
        }
        String signstr = Utils.byte2HexStrWithoutSpace(sign);
        System.out.println("签名：" + signstr + " ,长度：" + sign.length + " 字节");
        //4、根据证书原始数据和签名，生成开门凭证
        //4.1 byte数组格式
        byte[] openDoorCertificate = new byte[0];
        try {
            openDoorCertificate = Cerfiticate.generateOpenDoorCertificateWithByte(certificateOriginal, sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        String byteStr = Utils.byte2HexStrWithoutSpace(openDoorCertificate);
        System.out.println("开门凭证byte数组：" + byteStr + " ,长度：" + openDoorCertificate.length + " 字节");
        //4.2 base64格式
        String doorCertificateWithBase64 = "";
        try {
            doorCertificateWithBase64 = Cerfiticate.generateOpenDoorCertificateWithBase64(certificateOriginal, sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("开门凭证Base64：" + doorCertificateWithBase64 + " ,长度：" + doorCertificateWithBase64.length() / 2 + " 字节");
        byte[] Base64DecodeToByte = Base64.decode(doorCertificateWithBase64);
        String Base64DecodeToByteStr = Utils.byte2HexStrWithoutSpace(Base64DecodeToByte);
        System.out.println("开门凭证Base64转换为byte数组：" + Base64DecodeToByteStr + " ,长度：" + Base64DecodeToByteStr.length() / 2 + " 字节");
    }

    @Test
    public void test03() {
        int ordinal1 = Cerfiticate.TYPE.NONE.ordinal();
        int ordinal2 = Cerfiticate.TYPE.DEVICEID_RSA_OAEP.ordinal();
        int ordinal3 = Cerfiticate.TYPE.DEVICE_ECDSA_SHA256.ordinal();
        int ordinal4 = Cerfiticate.TYPE.FIX_ADDR_ECDSA_SHA256.ordinal();
        System.out.println("ordinal1 = " + ordinal1);
        System.out.println("ordinal2 = " + ordinal2);
        System.out.println("ordinal3 = " + ordinal3);
        System.out.println("ordinal4 = " + ordinal4);
    }
}