package detector;

import cn.ac.ios.Bean.Pair;
import detector.Analysis.Analysis;
import detector.Analysis.RepairType;
import regex.Pattern;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Vector;

public class SingleTester {
    public static String test(int id, String regex) {
        String regex_repaired = "";
        int count = 0;

        // 调试显示
        System.out.println("-----------------------------------------------------");
        System.out.println("Test " + id + ": " + regex);
        // print date and time
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();
        System.out.println(dateFormat.format(date));
        System.out.println("-----------------------------------------------------");
        do {
            Vector<Pair<String, RepairType>> result = Analysis.Analysis(regex, count);
            if (result.size() == 0) {
                break;
            }

            // 从result中随机选择一个作为regex_repaired
            int index = (int) (Math.random() * result.size());
            regex_repaired = result.get(index).getKey();

            // // 始终挑选第一个
            // regex_repaired = result.get(0).getKey();

            System.out.println("repaired: "+regex_repaired + "\n");
            regex = regex_repaired;
            count++;
        } while (!regex_repaired.equals("") && count < 10);

        System.out.println("final regex: "+regex);

        return regex;
    }

    public static void main(String[] args) {
        // // Analyzer k = new Analyzer("/(j_username\\x3D\\x26)?[^\\n]*j_password\\x3D(\\x26|$)([^\\n]*j_username\\x26(\\x26|$))?/");
        // String raw_regex = "\\x{59}";
        // // String raw_regex = "/a/i";
        // String regex = PreprocessingInterface.preprocess(raw_regex);
        // System.out.println("raw_regex:\n" + raw_regex);
        // System.out.println("regex:\n" + regex);

        // Pattern p = Pattern.compile("a");
        // p = Pattern.compile("[a]");
        // p = Pattern.compile("[\\w]");
        // p = Pattern.compile("\\d");
        // p = Pattern.compile("a*");
        // p = Pattern.compile("[a-z]+");
        // p = Pattern.compile(".?");
        // p = Pattern.compile("(a)");
        // p = Pattern.compile("(a)");
        // Pattern p = Pattern.compile("[a-z][A-Z]|[A-Z]{2,}[a-z]|[0-9][a-zA-Z]|[a-zA-Z][0-9]|[^a-zA-Z0-9 ]");
        // System.out.println(p.root.regex);
        // System.out.println(regexUtils.getNodeMermaidTree(".\\s\\S\\d\\D\\w\\W[a-zA-Z][ace]abca+(b|c)+(d)+"));


        // String regex = "^\\b\\B(a)+b(?:c)*d(1|2|e)?f(?=g)(?!h)(?<=i)(?<!j)\\1$";
        // // System.out.println(regexUtils.getNodeMermaidTree(regex));
        // Pattern p = Pattern.compile(regex);
        // Tree t = new Tree(p.root);
        // System.out.println(TreeUtils.getNodeMermaidTree(t));
        // System.out.println(t.generateRegex(t.root));
        // System.out.println(p.root.regex);

        // NQ
        // String regex = "(a*)+";
        // String regex = "/?(?P<events>([A-Z0-9_-]+/?)+)?";
        // String regex = "[&*$@%]#?(?:(?:::)*'?(?!\\d)[\\w$]+)+(?:::)*";
        // String regex = "(^|\\[[{(=:,\\s])(?:[^#\"\\',:=\\[\\]{}()\\s`-]|[:-][^\"\\',=\\[\\]{}()\\s])(?:[^,:=\\]})(\\s]+|:(?![\\s,\\]})]|$)|[ \\t]+[^#,:=\\]})(\\s])*";
        // String regex = "\\[([^\\[\\]]*|\\[[^\\[\\]]*\\])*\\]|([A-Za-z])\\2+|\\.{3}|.";
        // // String regex = "(?:\\[?(?:\\s*<![^>]*>\\s*)*\\]?)*";
        // // regex = PreProcess.preProcess(regex);
        // // // System.out.println(regexUtils.getNodeMermaidTree(regex));
        // // Pattern p = Pattern.compile(regex);
        // // Tree t = new Tree(p.root);
        // // System.out.println(TreeUtils.getNodeMermaidTree(t));
        // // System.out.println(t.generateRegex(t.root));
        // // // Analysis.Analysis(t);
        // // Analyzer a = new Analyzer(t);
        // System.out.println(Analysis.Analysis(regex).toString());

        // String regex = "^(\\d\\.|\\.\\d|\\d)+$"; // QOD1
        // String regex = "^(ab|a|b)+$"; // QOD1
        // String regex = "(?:[\\w-]|\\$[-\\w]+|#\\{\\$[\\-\\w]+\\})+(?=\\s*:)"; // QOD2
        // String regex = "((\\r|\\r?\\n).*)*abc"; // QOD2

        // String regex = "^((([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])+(\\.([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(\\\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.)+(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.?$"; // 无漏洞
        // String regex = "^\\|={3,}(?:(?:\\r?\\n|\\r).*)*?(?:\\r?\\n|\\r)\\|={3,}$";
        // String regex = "\"(?:[^\\\\\"\\r\\n]|\\\\(?:[abfnrtv\\\\\"]|\\d+|x[0-9a-fA-F]+))*\"";
        // String regex = "([\"'])(?:\\$\\{(?:[^'\"}]|([\"'])(?:(?!\\2)[^\\\\]|\\\\[\\s\\S])*\\2)+\\}|(?!\\1)[^\\\\]|\\\\[\\s\\S])*\\1"; // 时间太长
        // String regex = "(^|\\r?\\n|\\r)\\/[\\t ]*(?:(?:\\r?\\n|\\r)(?:.*(?:\\r?\\n|\\r))*?(?:\\\\(?=[\\t ]*(?:\\r?\\n|\\r))|$)|\\S.*)";
        // String regex = "(^[ \\t]*)(?:(?=\\S)(?:[^{}\\r\\n:()]|::?[\\w-]+(?:\\([^)\\r\\n]*\\))?|\\{[^}\\r\\n]+\\})+)(?:(?:\\r?\\n|\\r)(?:\\1(?:(?=\\S)(?:[^{}\\r\\n:()]|::?[\\w-]+(?:\\([^)\\r\\n]*\\))?|\\{[^}\\r\\n]+\\})+)))*(?:,$|\\{|(?=(?:\\r?\\n|\\r)(?:\\{|\\1[ \\t]+)))";
        // String regex = "(^[^\\S\\r\\n]*)---(?:\\r\\n?|\\n)(?:.*(?:\\r\\n?|\\n))*?[^\\S\\r\\n]*\\.\\.\\.$";
        // String regex = "^([-/:,#%.'\"\\s!\\w]|\\w-\\w|'[\\s\\w]+'\\s*|\"[\\s\\w]+\"|\\([\\d,%\\.\\s]+\\))*$";
        // String regex = "^((([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])+(\\.([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(\\\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.)+(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.?$";
        // String regex = "\"((?:\\\\[\\x00-\\x7f]|[^\\x00-\\x08\\x0a-\\x1f\\x7f\"])*)\"";
        // String regex = "((([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.)+";
        // System.out.println(Analysis.Analysis(regex).toString());

        // QOA
        // String regex = "((?:^|[^\\\\])(?:\\\\\\\\)*)\\$\\{(?:<expr>)*?\\}"; // 没漏洞
        // String regex = "^(?:(?:[\\w\\-#_= /:]*|[+]|[!])(\\(\\?P<\\w+>.+\\)))+$";
        // String regex = "^([^-]+)-([A-Za-z0-9+/=]{44,88})(\\?[\\x21-\\x7E]*)*$"; // 静态可以测得出，但动态测不出 // 考虑通过followlast和last来检测
        // String regex = "^(\\s|\\/\\*.*?\\*\\/)*[\\[\\(\\w]"; // 应该属于QOA3但没测出来，其中有一个子正则不是counting // 考虑通过followlast和last来检测
        // String regex = "^__[^\\W_]+\\w+__$"; // QOA1
        // String regex = "^(>=?|<=?)\\s*(\\d*\\.?\\d+)%$"; // QOA2暂时归类到QOA1
        // String regex = "@([\\w\\-]+\\.[\\w\\-:]+)+[:/]"; // QOA3
        // System.out.println(Analysis.Analysis(regex).toString());

        // // SLQ
        // String regex = "([A-Z]+)([A-Z][a-z])"; // SLQ1
        // regex = ".*\\."; // SLQ1
        // regex = "\\s*$"; // SLQ1
        // regex = "((?:(?:twaalf|zeven|negen|twee|drie|vier|vijf|acht|tien|een|zes|elf)|[0-9]+|[0-9]+\\.[0-9]+|een?|halve?))\\s*((?:seconden|minuten|maanden|second|minute|dagen|weken|maand|jaren|mins|uren|week|jaar|sec|min|hrs|uur|dag|hr|jr|h))\\s*";
        // regex = "\\$?[A-Z]+"; // SLQ2 没有后缀，没有SLQ
        // regex = "\\[[!\"#%&'()*+,-./{|}<>_~]+ (?:\\[[^\\]]+\\]|[^\\]])+\\]"; // SLQ3
        // regex = "Google.*/\\+/web/snippet"; // SLQ3
        // regex = "\\{([\\s\\S]+?)\\}"; // SLQ3
        // // regex = "[ab](ca+)+d"; // SLQ4
        // regex = "[ab](ca{1,2}da)+e"; // SLQ5
        // System.out.println(Analysis.Analysis(regex).toString());


        // 循环, 直到没有漏洞
        String regex = "(Opera)/9.80.*Version/(\\d+)\\.(\\d+)(?:\\.(\\d+)|)";
        String regex_repaired = "";
        int count = 0;
        do {
            Vector<Pair<String, RepairType>> result = Analysis.Analysis(regex, count);
            if (result.size() == 0) {
                break;
            }

            // 从result中随机选择一个作为regex_repaired
            int index = (int) (Math.random() * result.size());
            regex_repaired = result.get(index).getKey();

            // // 始终挑选第一个
            // regex_repaired = result.get(0).getKey();

            System.out.println("repaired: "+regex_repaired + "\n");
            regex = regex_repaired;
            count++;
        } while (!regex_repaired.equals("") && count < 10);

        System.out.println("final regex: "+regex);
    }
}
