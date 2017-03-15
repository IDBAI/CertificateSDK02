package com.revenco.certificatesdk;

import junit.framework.TestSuite;

import org.junit.Test;

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
}