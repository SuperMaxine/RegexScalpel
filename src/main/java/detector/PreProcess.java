package detector;

public class PreProcess {
    public static String preProcess(String regex) {
        // replace all "\(\?P<(.*)>" to "(?<$1>";
        String newRegex = regex.replaceAll("\\(\\?P<(.*)>", "(?<$1>");
        while (newRegex != regex){
            regex = newRegex;
            newRegex = regex.replaceAll("\\(\\?P<(.*)>", "(?<$1>");
        }
        return regex;
    }
}
