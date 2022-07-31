package cn.ac.ios.EngineValidation.Java8;

import cn.ac.ios.EngineValidation.Java8.regex.Pattern;

public class Main {
    /**
     * add by czx
     * @param validationFunction if validationFunction = 'matches', then call Trace.match(); else call Trace.find();
     * @return
     */
    public static boolean checkResult(Pattern pattern, String prefix, String pump, String suffix, int maxLength, int threshold, String validationFunction) {
        if (pump.length() == 0) return false;
        int matchingStepCnt = 0;
        matchingStepCnt = pattern.getMatchingStepCnt(prefix, pump, suffix, maxLength, threshold, validationFunction);
        if (matchingStepCnt >= threshold)
            return true;
        return false;
    }

    public static void main(String[] args) {
        String regex = "(a*)*$";
        String prefix = "";
        String attack_core = "a";
        String suffix = "!a!";
        int max_length = 12800;
        int threshold = 100000;
        Pattern p = Pattern.compile(regex);
        System.out.println(checkResult(p, prefix, attack_core, suffix, max_length, threshold, "matches"));
        System.out.println(checkResult(p, prefix, attack_core, suffix, max_length, threshold, "find"));
    }
}
