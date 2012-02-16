package cn.com.emv.certmgr;


public class CodeGenerator {

    private static final char[] REF_SRC = { 
    	'0', '1', '2', '3', '4', '5', '6', '7', 
    	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    
    private static final char[] REF_SRC_0 = {
    	'1', '2', '3', '4', '5', '6', '7'
    };

    // default cert sn code length
    public static final int DEFAULT_CODE_LEN = 16;


    public static String generateSerialNumber() {
        StringBuffer stBuffer = new StringBuffer();
        
        // 1st digital
        int r0 = (int) (Math.random() * REF_SRC_0.length);
        stBuffer.append(REF_SRC_0[r0]);

        // generate random reference code from REF_SRC
        for (int i = 1; i < DEFAULT_CODE_LEN; i++) {
            int r = (int) (Math.random() * REF_SRC.length);
            stBuffer.append(REF_SRC[r]);
        }
        
        return stBuffer.toString();
    }
}
