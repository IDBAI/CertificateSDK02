package com.revenco.certificatesdk;

import junit.framework.TestSuite;

import org.junit.Test;

import java.security.Provider;
import java.security.Security;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest extends TestSuite {
    @Test
    public void baseTest() {
        for (int i = 0; i < 100 * 10000; i++) {
            ECDSATest.getIntance().baseTest();
        }
        System.out.println("测试完成");
    }

    @Test
    public void signChange() {
        ECDSATest.getIntance().baseTest();
        ECDSATest.getIntance().signChangeTest(100 * 10000, true);
        System.out.println("测试完成");
    }

    /**
     * 内容被修改，随机修改次数，随机修改位置
     */
    @Test
    public void contentChange() {
        ECDSATest.getIntance().baseTest();
        ECDSATest.getIntance().contentChangeTest(100 * 10000);
        System.out.println("测试完成");
    }

    @Test
    public void mutilChange() {
        ECDSATest.getIntance().baseTest();
        ECDSATest.getIntance().multSignMultVerify(1000, 1000);
        System.out.println("测试完成");
    }


    @Test
    public void Check() {
        System.out.println("-------列出加密服务提供者-----");
        Provider[] pro = Security.getProviders();
        for (Provider p : pro) {
            System.out.println("Provider:" + p.getName() + " - version:" + p.getVersion());
            System.out.println(p.getInfo());
        }
        System.out.println("");
        System.out.println("-------列出系统支持的消息摘要算法：");
        for (String s : Security.getAlgorithms("MessageDigest")) {
            System.out.println(s);
        }
        System.out.println("-------列出系统支持的生成公钥和私钥对的算法：");
        for (String s : Security.getAlgorithms("KeyPairGenerator")) {
            System.out.println(s);
        }

    }
}