package com.revenco.ecdsalibrary.core;

import com.revenco.ecdsalibrary.common.Utils;

import org.spongycastle.util.encoders.Base64;

import java.security.PrivateKey;

/**
 * Created by Administrator on 2017/2/14.
 * 证书生成类
 */
public class Cerfiticate {
    /**
     * 生成原始证书数据 57 字节长度
     *
     * @param type        类型，保留字段，1字节
     * @param userId      用户id 16字节
     * @param userBleMac  手机MAC地址 6字节
     * @param deviceId    设备id 16字节
     * @param channelMask 通道掩码 1字节
     * @param issueTime   签发时间 4字节（默认为当前时间）
     * @param timeout     失效时间 4字节
     * @param counter     计数器 8字节
     * @param useTimes    使用次数 1字节
     * @return
     * @throws Exception
     * @deprecated <p>
     * 请使用新的方法{@link Cerfiticate#genCertifiOriginalV2(TYPE, byte[], byte[], byte[], byte[], byte[], byte[], byte[], byte[])}
     * </p>
     */
    public static byte[] generateCertificateOriginal(byte[] type, byte[] userId, byte[] userBleMac,
                                                     byte[] deviceId, byte[] channelMask, byte[] issueTime,
                                                     byte[] timeout, byte[] counter, byte[] useTimes) throws Exception {
        if (type.length != 1) {
            throw new Exception("type.length must be 1 byte size!");
        }
        if (userId.length != 16) {
            throw new Exception("userid.length must be 16 byte size!");
        }
        if (userBleMac.length != 6) {
            throw new Exception("userBleMac.length must be 6 byte size!");
        }
        if (deviceId.length != 16) {
            throw new Exception("deviceid.length must be 16 byte size!");
        }
        if (channelMask.length != 1) {
            throw new Exception("channelMask.length nust be 1 byte size!");
        }
        if (issueTime.length != 4) {
            throw new Exception("issueTime.length must be 4 byte size!");
        }
        if (timeout.length != 4) {
            throw new Exception("timeout.length must be 4 byte size!");
        }
        if (counter.length != 8) {
            throw new Exception("counter.length must be 8 byte size!");
        }
        if (useTimes.length != 1) {
            throw new Exception("useTimes.length must be 1 byte size!");
        }
        byte[] certificate = Utils.merge(type, userId, userBleMac,
                deviceId, channelMask, issueTime,
                timeout, counter, useTimes);
        return certificate;
    }

    /**
     * 生成原始证书数据 57 字节长度
     *
     * @param type        类型，此方法仅仅支持 TYPE.FIX_ADDR_ECDSA_SHA256 类型
     * @param userId      用户id 16字节
     * @param userBleMac  手机MAC地址 6字节
     * @param deviceMark  设备标识采用固定的设备地址来替代，详情参考：云盘： 产品研发\MT1100系列研发\MVO1600门口机研发\06 APP设计\02 设计\BLE开门迭代设计\基于BLE和WIFI-AP的离线开门的实现.pdf
     * @param channelMask 通道掩码 1字节
     * @param issueTime   签发时间 4字节（默认为当前时间）
     * @param timeout     失效时间 4字节
     * @param counter     计数器 8字节
     * @param useTimes    使用次数 1字节
     * @return
     * @throws Exception
     */
    public static byte[] genCertifiOriginalV2(
            TYPE type, byte[] userId, byte[] userBleMac,
            byte[] deviceMark, byte[] channelMask, byte[] issueTime,
            byte[] timeout, byte[] counter, byte[] useTimes) throws Exception {
        if (type != TYPE.FIX_ADDR_ECDSA_SHA256) {
            throw new Exception("type must be TYPE.FIX_ADDR_ECDSA_SHA256 !");
        }
        if (userId.length != 16) {
            throw new Exception("userid.length must be 16 byte size!");
        }
        if (userBleMac.length != 6) {
            throw new Exception("userBleMac.length must be 6 byte size!");
        }
        if (deviceMark.length != 16) {
            throw new Exception("deviceid.length must be 16 byte size!");
        }
        if (channelMask.length != 1) {
            throw new Exception("channelMask.length nust be 1 byte size!");
        }
        if (issueTime.length != 4) {
            throw new Exception("issueTime.length must be 4 byte size!");
        }
        if (timeout.length != 4) {
            throw new Exception("timeout.length must be 4 byte size!");
        }
        if (counter.length != 8) {
            throw new Exception("counter.length must be 8 byte size!");
        }
        if (useTimes.length != 1) {
            throw new Exception("useTimes.length must be 1 byte size!");
        }
        byte[] typebyte = new byte[]{(byte) type.ordinal()};
        byte[] certificate = Utils.merge(typebyte, userId, userBleMac,
                deviceMark, channelMask, issueTime,
                timeout, counter, useTimes);
        return certificate;
    }

    /**
     * 生成证书签名
     *
     * @param privateKey
     * @param certificateOriginal
     * @return
     * @throws Exception
     */
    public static byte[] generateCertificateSign(PrivateKey privateKey, byte[] certificateOriginal) throws Exception {
        if (privateKey == null) {
            throw new Exception("privateKey is null!");
        }
        if (certificateOriginal == null || certificateOriginal.length == 0) {
            throw new Exception("certificateOriginal is empty!");
        }
        byte[] sign = ECDSA.generateSign(privateKey, certificateOriginal);
        return sign;
    }

    /**
     * @param certificateOriginal
     * @param certificateSign
     * @return
     * @throws Exception
     */
    public static byte[] generateOpenDoorCertificateWithByte(byte[] certificateOriginal, byte[] certificateSign) throws Exception {
        if (certificateOriginal == null || certificateOriginal.length == 0) {
            throw new Exception("certificateOriginal is empty!");
        }
        if (certificateSign == null || certificateSign.length == 0) {
            throw new Exception("certificateSign is empty!");
        }
        byte[] originalLength = new byte[1];
        originalLength[0] = (byte) certificateOriginal.length;
        byte[] signLength = new byte[1];
        signLength[0] = (byte) certificateSign.length;
        byte[] openDoor = Utils.merge(originalLength, certificateOriginal, signLength, certificateSign);
        return openDoor;
    }

    /**
     * @param certificateOriginal
     * @param certificateSign
     * @return
     * @throws Exception
     */
    public static String generateOpenDoorCertificateWithBase64(byte[] certificateOriginal, byte[] certificateSign) throws Exception {
        byte[] openDoor = generateOpenDoorCertificateWithByte(certificateOriginal, certificateSign);
        String base64String = Base64.toBase64String(openDoor);
        return base64String;
    }

    public enum TYPE {
        NONE,
        DEVICEID_RSA_OAEP,
        DEVICE_ECDSA_SHA256,
        FIX_ADDR_ECDSA_SHA256,
    }
}
