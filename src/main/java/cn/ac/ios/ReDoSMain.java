package cn.ac.ios;

import cn.ac.ios.Patterns.SLQ.PatternSLQUtils3;
import cn.ac.ios.TreeNode.TreeNode;
import cn.ac.ios.Bean.AttackBean;
import cn.ac.ios.Bean.ReDoSBean;
import cn.ac.ios.Bean.RegexBean;
import cn.ac.ios.Patterns.EOA.PatternEOAUtils4;
import cn.ac.ios.Patterns.EOD.PatternEODUtils3;
import cn.ac.ios.Patterns.NQ.PatternNQUtils;
import cn.ac.ios.Patterns.POA.PatternPOAUtils2;
import cn.ac.ios.Patterns.SLQ.PatternSLQUtils;
import org.apache.commons.io.FileUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static cn.ac.ios.TreeNode.Utils.createReDoSTree;
import static cn.ac.ios.TreeNode.Utils.deleteAnnotation;
import static cn.ac.ios.Utils.Constant.EXTENDED_COUNTING;
import static cn.ac.ios.Utils.FlagsUtils.*;

/**
 * @author pqc
 */
public class ReDoSMain {

    public static String PYTHON = "python3";
    public static String JS = "node";

    public static void main(String[] args) throws IOException, InterruptedException {

        String regex = "([\\d\\w-.]+?\\.(a[cdefgilmnoqrstuwz]|b[abdefghijmnorstvwyz]|c[acdfghiklmnoruvxyz]|d[ejkmnoz]|e[ceghrst]|f[ijkmnor]|g[abdefghilmnpqrstuwy]|h[kmnrtu]|i[delmnoqrst]|j[emop]|k[eghimnprwyz]|l[abcikrstuvy]|m[acdghklmnopqrstuvwxyz]|n[acefgilopruz]|om|p[aefghklmnrstwy]|qa|r[eouw]|s[abcdeghijklmnortuvyz]|t[cdfghjkmnoprtvwz]|u[augkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw]|aero|arpa|biz|com|coop|edu|info|int|gov|mil|museum|name|net|org|pro)(\\b|\\W(?<!&|=)(?!\\.\\s|\\.{3}).*?))(\\s|$)";
        regex = "<(?![!/]?[ABIU][>\\s])[^>]*>";
        regex = "((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\\W_]).{6,50})";
        regex = "/<object\\s*[^>]*\\s*classid\\s*=\\s*(?P<q1>\\x22|\\x27|)\\s*clsid\\s*\\x3a\\s*{?\\s*0002E510-0000-0000-C000-000000000046\\s*}?\\s*(?P=q1)(\\s|>)/si";
        regex = "\\b(([\\w-]+://?|www[.])[^\\s()<>]+(?:\\([\\w\\d]+\\)|([^[:punct:]\\s]|/)))";
        regex = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+";
        regex = "(ab[abc]+ab)+d";
        regex = "/^(?:(?:(?:https?|ftp):)?\\/\\/)(?:\\S+(?::\\S*)?@)?(?:(?!(?:10|127)(?:\\.\\d{1,3}){3})(?!(?:169\\.254|192\\.168)(?:\\.\\d{1,3}){2})(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)(?:\\.(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)*(?:\\.(?:[a-z\\u00a1-\\uffff]{2,})).?)(?::\\d{2,5})?(?:[/?#]\\S*)?$/i";
        regex = "(\\\"([^\\\"]+|\\\"\\\")*\\\"|([^,]*))";
//        regex = "^(\\\\[\\w\\-()]+(\\s[\\w\\-()]+)*)+(\\\\(([\\w\\-()]+(\\s[\\w\\-()]+)*)+\\.[\\w]+)?)?$";
        regex = "^[-]?P(?!$)(?:(?<year>\\d+)+Y)?(?:(?<month>\\d+)+M)?(?:(?<days>\\d+)+D)?(?:T(?!$)(?:(?<hours>\\d+)+H)?(?:(?<minutes>\\d+)+M)? (?:(?<seconds>\\d+(?:\\.\\d+)?)+S)?)?$";
        regex = "(([\\n,  ])*((<+)([^<>]+)(>*))+([\\n,  ])*)+";
        regex = "<\\s*[\\/]?(?<tag>[a-z:_][-a-z0-9._:]*)(\\s+(?<attributes>[a-z:_]*[-a-z0-9._:]*[^\\s=><]*)\\s*=?\\s*(\"[^\"]*\"|'[^']*'|\"|')*[^\\s><]*)*\\s*[\\/]?>?";
        regex = "([0-9]* {0,2}[A-Z]{1}\\w+[,.;:]? {0,4}[xvilcXVILC\\d]+[.,;:]( {0,2}[\\d-,]{1,7})+)([,.;:] {0,4}[xvilcXVILC]*[.,;:]( {0,2}[\\d-,]{1,7})+)*";
        regex = "^\\s*((?:(?:\\d+(?:\\x20+\\w+\\.?)+(?:(?:\\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\\.?)?)|(?:(?:P\\.\\x20?O\\.|P\\x20?O)\\x20*Box\\x20+\\d+)|(?:General\\x20+Delivery)|(?:C[\\\\\\/]O\\x20+(?:\\w+\\x20*)+))\\,?\\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\\x23)\\.?\\x20*(?:[a-zA-Z0-9\\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)\\,?\\s+((?:(?:\\d+(?:\\x20+\\w+\\.?)+(?:(?:\\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\\.?)?)|(?:(?:P\\.\\x20?O\\.|P\\x20?O)\\x20*Box\\x20+\\d+)|(?:General\\x20+Delivery)|(?:C[\\\\\\/]O\\x20+(?:\\w+\\x20*)+))\\,?\\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\\x23)\\.?\\x20*(?:[a-zA-Z0-9\\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)?\\,?\\s+((?:[A-Za-z]+\\x20*)+)\\,\\s+(A[LKSZRAP]|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ADEHINOPST]|N[CDEHJMVY]|O[HKR]|P[ARW]|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\\s+(\\d+(?:-\\d+)?)\\s*$";
        regex = "((?:[^\\n]+\\n?)+)\\n*";
        regex = "L?\\s*([\\-\\d\\.e]+)[\\s,]*([\\-\\d\\.e]+)*";
        regex = "&lt;(span|font).*?(?:(?:(\\s?style=&quot;?).*?((?:\\s?font-size:.+?\\s*(?:;|,|(?=&quot;))+)|(?:\\s?color:.+?\\s*(?:;|,|(?=&quot;))+))[^&quot;]*((?:\\s?font-size:.+?\\s*(?:;|,|(?=&quot;))+)|(?:\\s?color:.+?\\s*(?:;|,|(?=&quot;))+))[^&quot;]*(&quot;?)|(\\s?size=&quot;?.*?(?:(?=\\s)|&quot;|(?=&gt;)))|(\\s?color=&quot;?.*?(?:(?=\\s)|&quot;|(?=&gt;)))|(?=&gt;)).*?){3}&gt;";
        regex = "(?<name>.+?)(?=-\\d)-(?<version>.+)";
        regex = "((v|[\\\\/])\\W*[i1]\\W*[a@]\\W*g\\W*r\\W*[a@]|v\\W*[i1]\\W*[c]\\W*[o0]\\W*d\\W*[i1]\\W*n)";
        regex = "^(?=.*[1-9].*$)\\d{0,7}(?:\\.\\d{0,9})?$";
        regex = "^\\-?\\(?([0-9]{0,3}(\\,?[0-9]{3})*(\\.?[0-9]*))\\)?$";    // 为什么这个会测两个呢？
        regex = "<!*[^<>]*>";
        regex = "http://www\\.youtube\\.com.*v=([^&]*)";
        regex = "^[-+]?(\\d?\\d?\\d?,?)?(\\d{3}\\,?)*(\\.?\\d+)$";  // 这个也测两个
        regex = "\\s*(([^,]|(,\\s*\\d))+)";
        regex = "[^A-Z]+(.*)";  // 这个不稳定 有时候可能会到8000ms
        regex = "^(\\t*)START\\t----\\t([^\\t]+).*$";   // 这个也不稳定 会到6000ms
        regex = "/~([^/]+)(.*)";    // 这个也不稳定 会到8500ms
        regex = "/\\(\\s*(\\x27[^\\x27]*'|\\x22[^\\x22]+\\x22)\\s*,(\\s*(true|false)\\s*,\\s*){3,}((\\x27[^\\x27]{1000,})|(\\x22[^\\x22]{1000,}))/Rmsi";
        regex = "([a-z\\s.\\-_'])*<\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*\\>|^\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*";
        regex = "((ht|f)tp(s?))(:((\\/\\/)(?!\\/)))(((w){3}\\.)?)([a-zA-Z0-9\\-_]+(\\.(com|edu|gov|int|mil|net|org|biz|info|name|pro|museum|co\\.uk)))(\\/(?!\\/))(([a-zA-Z0-9\\-_\\/]*)?)([a-zA-Z0-9])+\\.((jpg|jpeg|gif|png)(?!(\\w|\\W)))";
        regex = "\\[bible\\](([a-zäëïöüæø]*[[:space:]]{1}([a-zäëïöüæø]*[[:space:]]?[a-zäëïöüæø]*[[:space:]]{1})?)([0-9]{1,3})(:{1}([0-9]{1,3})(-{1}([0-9]{1,3}))?)?)\\[\\\\\\/bible\\]";
        regex = "\\[bible\\][a-zäëïöüæø]*[[:space:]]{1}([a-zäëïöüæø]*[a-zäëïöüæø]*)$";
        regex = "/^Location\\x3a(\\s*|\\s*\\r?\\n\\s+)*URL\\s*\\x3a/smiH";
        regex = "^(([a-z])+.)+[A-Z]([a-z])+$";
        regex = "^\\s*[+-]?\\s*(?:\\d{1,3}(?:(,?)\\d{3})?(?:\\1\\d{3})*(\\.\\d*)?|\\.\\d+)\\s*$";
        regex = "^([a-z]+?\\.[a-z]+)+\\%$";
        regex = "(?:(?:http|https):\\/\\/(?:(?:[^\\/&=()\\/§, ]*?)*\\.)+(?:\\w{2,3})+?)(?:\\/+[^ ?,'§$&()={\\[\\]}]*)*(?:\\?+.*)?$";
        regex = "/class\\s+([a-z0-9_]+)(?:\\s+extends\\s+[a-z0-9_]+)?(?:\\s+implements\\s+(?:[a-z0-9_]+\\s*,*\\s*)+)?\\s*\\{/Usi";
        regex = "/(?:[^a-z0-9_]+)+/Usi";
        regex = "/class\\s+([a-z0-9_]+)(?:\\s+extends\\s+[a-z0-9_]+)?(?:\\s+implements\\s+(?:[a-z0-9_]+\\s*,*\\s*)+)?\\s*\\{/Usi";
        regex = "<\\w+[^>]*>|<\\/\\w+>|[\\w\\']+|\\s+|[^\\w\\'\\s<>\\/]+";
        regex = "([\\d\\w-.]+?\\.(a[cdefgilmnoqrstuwz]|b[abdefghijmnorstvwyz]|c[acdfghiklmnoruvxyz]|d[ejkmnoz]|e[ceghrst]|f[ijkmnor]|g[abdefghilmnpqrstuwy]|h[kmnrtu]|i[delmnoqrst]|j[emop]|k[eghimnprwyz]|l[abcikrstuvy]|m[acdghklmnopqrstuvwxyz]|n[acefgilopruz]|om|p[aefghklmnrstwy]|qa|r[eouw]|s[abcdeghijklmnortuvyz]|t[cdfghjkmnoprtvwz]|u[augkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw]|aero|arpa|biz|com|coop|edu|info|int|gov|mil|museum|name|net|org|pro)(\\b|\\W(?<!&|=)(?!\\.\\s|\\.{3}).*?))(\\s|$)";
        regex = "(?s)( class=\\w+(?=([^&lt;]*&gt;)))|(&lt;!--\\[if.*?&lt;!\\[endif\\]--&gt;)|(&lt;!\\[if !\\w+\\]&gt;)|(&lt;!\\[endif\\]&gt;)|(&lt;o:p&gt;[^&lt;]*&lt;/o:p&gt;)|(&lt;span[^&gt;]*&gt;)|(&lt;/span&gt;)|(font-family:[^&gt;]*[;'])|(font-size:[^&gt;]*[;'])(?-s)";
        regex = "(?s)(\\w+(?=([^&lt;]*&gt;)))(?-s)";
        regex = "@rx (?i)(?:[\\\"'`]\\s*?(?:(?:n(?:and|ot)|(?:x?x)?or|between|\\|\\||and|div|&&)\\s+[\\s\\w]+=\\s*?\\w+\\s*?having\\s+|like(?:\\s+[\\s\\w]+=\\s*?\\w+\\s*?having\\s+|\\W*?[\\\"'`\\d])|[^?\\w\\s=.,;)(]+\\s*?[(@\\\"'`]*?\\s*?\\w+\\W+\\w|\\*\\s*?\\w+\\W+[\\\"'`])|(?:union\\s*?(?:distinct|[(!@]*?|all)?\\s*?[(\\[]*?\\s*?select|select\\s+?[\\[\\]()\\s\\w\\.,\\\"'`-]+from)\\s+|\\w+\\s+like\\s+[\\\"'`]|find_in_set\\s*?\\(|like\\s*?[\\\"'`]%)(?-i)";
        regex = "^\\s+|\\s*$";
        // regex = "(a*)*";
        ReDoSBean bean = validateReDoS(checkReDoS(regex, 1, "11111", "java"), "s", "java");
        System.out.println(bean.getRegex());
//        ReDosBean bean = checkReDos(regex, 1, "00010");
        for (int i = 0; i < bean.getAttackBeanList().size(); i++) {
//            if (bean.getAttackBeanList().get(i).isAttackSuccess()) {
            System.out.println(bean.getAttackBeanList().get(i).getAttackTime());
            System.out.println(bean.getAttackBeanList().get(i).getLocateVulnerabilityRegex());
            System.out.println(bean.getAttackBeanList().get(i).getAttackStringFormat());
            System.out.println(bean.getAttackBeanList().get(i).getVulnerabilityRegexSource());
//            System.out.println(bean.getAttackBeanList().get(i).getPatternType());
//                System.out.println(bean.getAttackBeanList().get(i).getConflictPoint().getKey() + "  " + bean.getAttackBeanList().get(i).getConflictPoint().getValue());
//                System.out.println(Arrays.toString(bean.getAttackBeanList().get(i).getConflictIndex().getKey()) + "  " + Arrays.toString(bean.getAttackBeanList().get(i).getConflictIndex().getValue()));
//            }
        }
    }

    /**
     * 获取正则的判断结果
     * 阶段一：检测
     *
     * @param regex
     * @param id
     * @return
     */
    public static ReDoSBean checkReDoS(String regex, Integer id, String options, String language) {
        ReDoSBean bean = new ReDoSBean();
        bean.setRegex(regex);
        bean.setId(id);
        bean.setRegexID(id);
        if (mustBeNoReDoS(regex)) {
            bean.setMessage("MUST_NOT_BE_REDOS");
            return bean;
        }
//        String suffix = PatternPOAUtils.getSuffix(regex);

        if (options.charAt(0) == '1') {
//            System.out.println("getNQReDoSBean start");
            ReDoSBean bean1 = PatternNQUtils.getNQReDoSBean(regex, language);
            bean.getAttackBeanList().addAll(bean1.getAttackBeanList());
        }

        if (options.charAt(1) == '1') {
//            System.out.println("getEODReDoSBean start");
            ReDoSBean bean2 = PatternEODUtils3.getEODReDoSBean(regex, language);
            bean.getAttackBeanList().addAll(bean2.getAttackBeanList());
        }

        if (options.charAt(2) == '1') {
//            System.out.println("getEOAReDoSBean start");
            ReDoSBean bean3 = PatternEOAUtils4.getEOAReDoSBean(regex, language);
            bean.getAttackBeanList().addAll(bean3.getAttackBeanList());
        }

        if (options.charAt(3) == '1') {
//            System.out.println("getPOAReDoSBean start");
//            ReDosBean bean4 = PatternPOAUtils.getPOARedosBean(regex);
//            bean.getAttackBeanList().addAll(bean4.getAttackBeanList());
            ReDoSBean bean4 = PatternPOAUtils2.getPOAReDoSBean(regex, language);
            bean.getAttackBeanList().addAll(bean4.getAttackBeanList());
        }

        if (options.charAt(4) == '1') {
//            System.out.println("getSLQReDoSBean start");
//            ReDoSBean bean5 = PatternSLQUtils.getSLQReDoSBean(regex, language);
            ReDoSBean bean5 = PatternSLQUtils3.getSLQReDoSBean(regex, language);
            bean.getAttackBeanList().addAll(bean5.getAttackBeanList());
        }

//        for (AttackBean attackBean : bean.getAttackBeanList()) {
//            PatternType patternType = attackBean.getPatternType();
//            if (patternType == PatternType.SLQ_1 || patternType == PatternType.SLQ_2 ||
//                    patternType == PatternType.SLQ_3 || patternType == PatternType.SLQ2
//            ) {
//                attackBean.setSuffix(attackBean.getSuffix() + suffix);
//            }
//        }

        return bean;
    }

    /**
     * 获取正则的判断结果
     * 阶段一：检测
     *
     * @param regex
     * @param id
     * @return
     */
    public static ReDoSBean checkReDoS(String regex, Integer id) {
        return checkReDoS(regex, id, "11111", "java");
    }

    /**
     * 利用攻击串验证判断结果
     * 阶段二：验证
     *
     * @param bean
     * @return
     */
    public static ReDoSBean validateReDoS(ReDoSBean bean, String model, String language) {
        bean.setReDoS(false);
        if (bean.getAttackBeanList().isEmpty()) {
            return bean;
        }
        bean.duplicate();
        if ("python".equals(language)) {
            return getPython(bean, model);
        } else if ("js".equals(language)) {
            return getJS(bean, model);
        } else {
//            return getJava(bean, model);
            return fastValidateByJava8(bean, model);
        }
    }

    // 快速验证 通过使用java8的正则引擎
    public static ReDoSBean fastValidateByJava8(ReDoSBean bean, String model) {
        RegexBean divideRegexByFlagsBean = divideRegexByFlags(bean.getRegex());
        String newRegex = divideRegexByFlagsBean.getRegex();
        String allFlags = divideRegexByFlagsBean.getAllFlags();
        if (allFlags.contains("s")) {
            newRegex = "(?s)" + newRegex;
        }
        if (allFlags.contains("i")) {
            newRegex = "(?i)" + newRegex;
        }
        if (allFlags.contains("m")) {
            newRegex = "(?m)" + newRegex;
        }
        if (allFlags.contains("x")) {
            newRegex = "(?x)" + newRegex;
        }
        bean.setRegex(newRegex);

//        bean.setRegex(divideRegexByFlags(bean.getRegex()).getRegex());
        try {
            Pattern.compile(bean.getRegex());
        } catch (Exception e) {
            try {
//                String regex = deleteGroupName(bean.getRegex());

                // 最开头的预处理
//                regex = rewriteRegex(regex);
//                regex = reduceLocalFlags(regex);
//                regex = removeAnnotationByFlagX(regex);
//                regex = processLocalFlag(regex);
//                regex = replaceLocalFlagGM(regex);
                String regex = bean.getRegex();
                // 建树
                TreeNode ReDoSTree = createReDoSTree(regex);
                // 删除注释
                ReDoSTree.deleteAnnotation();
                // 去group name
                ReDoSTree.deleteGroupName();
                // 针对snort数据集中出现的{?写法 需要在{前加\ 暂不知是否还有其他需要加斜杠的
                ReDoSTree.addBackslashBeforeSomeCharacters();
                // 将方括号中的\0~\777重写为\u0000~\u0777
                ReDoSTree.rewriteUnicodeNumberInBracketNode();
                // 将方括号中的\b删除 因为方括号中的\b表示退格符
                ReDoSTree.reWriteBackspace();
                // 转换[\w-.] -> [\w\-.] 而 [a-z]保留 为了regexlib
                ReDoSTree.rewriteIllegalBarSymbol();
                // 处理特殊斜杠字符 根据不同的语言
                ReDoSTree.rewriteSpecialBackslashCharacterForDifferentLanguage("java");

                regex = ReDoSTree.getData();
                bean.setRegex(regex);
            } catch (Exception exception) {
                bean.setReDoS(false);
                return bean;
            }
        }
        bean.fastAttack(model);
        return bean;
    }

    /**
     * 使用java语言验证
     *
     * @param bean
     * @param model
     * @return
     */
    public static ReDoSBean getJava(ReDoSBean bean, String model) {
        RegexBean divideRegexByFlagsBean = divideRegexByFlags(bean.getRegex());
        String newRegex = divideRegexByFlagsBean.getRegex();
        String allFlags = divideRegexByFlagsBean.getAllFlags();
        if (allFlags.contains("s")) {
            newRegex = "(?s)" + newRegex;
        }
        if (allFlags.contains("i")) {
            newRegex = "(?i)" + newRegex;
        }
        if (allFlags.contains("m")) {
            newRegex = "(?m)" + newRegex;
        }
        if (allFlags.contains("x")) {
            newRegex = "(?x)" + newRegex;
        }
        bean.setRegex(newRegex);

//        bean.setRegex(divideRegexByFlags(bean.getRegex()).getRegex());
        try {
            Pattern.compile(bean.getRegex());
        } catch (Exception e) {
            try {
//                String regex = deleteGroupName(bean.getRegex());

                // 最开头的预处理
//                regex = rewriteRegex(regex);
//                regex = reduceLocalFlags(regex);
//                regex = removeAnnotationByFlagX(regex);
//                regex = processLocalFlag(regex);
//                regex = replaceLocalFlagGM(regex);
                String regex = bean.getRegex();
                // 建树
                TreeNode ReDoSTree = createReDoSTree(regex);
                // 删除注释
                ReDoSTree.deleteAnnotation();
                // 去group name
                ReDoSTree.deleteGroupName();
                // 针对snort数据集中出现的{?写法 需要在{前加\ 暂不知是否还有其他需要加斜杠的
                ReDoSTree.addBackslashBeforeSomeCharacters();
                // 将方括号中的\0~\777重写为\u0000~\u0777
                ReDoSTree.rewriteUnicodeNumberInBracketNode();
                // 将方括号中的\b删除 因为方括号中的\b表示退格符
                ReDoSTree.reWriteBackspace();
                // 转换[\w-.] -> [\w\-.] 而 [a-z]保留 为了regexlib
                ReDoSTree.rewriteIllegalBarSymbol();
                // 处理特殊斜杠字符 根据不同的语言
                ReDoSTree.rewriteSpecialBackslashCharacterForDifferentLanguage("java");

                regex = ReDoSTree.getData();
                bean.setRegex(regex);
            } catch (Exception exception) {
                bean.setReDoS(false);
                return bean;
            }
        }
        bean.attack(model);
        return bean;
    }


    /**
     * 使用python语言验证
     *
     * @param bean
     * @param model
     * @return
     */
    public static ReDoSBean getPython(ReDoSBean bean, String model) {
        bean.setRegex(divideRegexByFlags(bean.getRegex()).getRegex());
        System.out.println("waring:Your environment must support the command \"python3\" and sot support for Windows");
        List<String> list = new ArrayList<>();
        list.add(bean.getRegex());
        list.add(model);
        for (int i = 0; i < bean.getAttackBeanList().size(); i++) {
            AttackBean attackBean = bean.getAttackBeanList().get(i);
            list.add(attackBean.getType().name());
            list.add(attackBean.getAttackStringFormatSp());
        }
        String name = System.currentTimeMillis() + "python_attack.txt";
        try {
            FileUtils.writeLines(new File("python/" + name), list);

            Process proc;
            String[] args = new String[]{PYTHON, "python/attack.py", "python/" + name};
            proc = Runtime.getRuntime().exec(args);// 执行py文件
            //用输入输出流来截取结果
            BufferedReader in = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line = null;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
            in.close();
            proc.waitFor();
            ArrayList<String> results = (ArrayList<String>) FileUtils.readLines(new File("python/" + name.replace(".txt", "_result.txt")), "utf-8");
            for (int i = 0; i < bean.getAttackBeanList().size(); i++) {
                String[] s = results.get(i).toLowerCase().split("IOS_AC_CN".toLowerCase());
                bean.getAttackBeanList().get(i).setAttackSuccess(Boolean.parseBoolean(s[0]));
                if (Boolean.parseBoolean(s[0])) {
                    bean.setReDoS(true);
                }
                bean.getAttackBeanList().get(i).setRepeatTimes(Integer.parseInt(s[1]));
                bean.getAttackBeanList().get(i).setAttackTime(Integer.parseInt(s[2]));
            }
            return bean;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            FileUtils.deleteQuietly(new File("python/" + name));
            FileUtils.deleteQuietly(new File("python/" + name.replace(".txt", "_result.txt")));
        }
        return bean;
    }

    /**
     * 使用python语言验证
     *
     * @param bean
     * @param model
     * @return
     */
    public static ReDoSBean getJS(ReDoSBean bean, String model) {
        System.out.println("waring:Your environment must support the command \"node\"");
        List<String> list = new ArrayList<>();
        String regex = divideRegexByFlags(bean.getRegex()).getRegex();
        String flags = divideRegexByFlags(bean.getRegex()).getFlags();
        list.add(regex);
        list.add(flags);
        list.add(model);
        for (int i = 0; i < bean.getAttackBeanList().size(); i++) {
            AttackBean attackBean = bean.getAttackBeanList().get(i);
            list.add(attackBean.getType().name());
            list.add(attackBean.getAttackStringFormatSp());
        }
        String name = System.currentTimeMillis() + "js_attack.txt";
        try {
            FileUtils.writeLines(new File("js/" + name), list);

            Process proc;
            String[] args = new String[]{JS, "js/attack.js", "js/" + name};
            proc = Runtime.getRuntime().exec(args);// 执行py文件
            //用输入输出流来截取结果
            BufferedReader in = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line = null;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
            in.close();
            proc.waitFor();
            ArrayList<String> results = (ArrayList<String>) FileUtils.readLines(new File("js/" + name.replace(".txt", "_result.txt")), "utf-8");
            for (int i = 0; i < bean.getAttackBeanList().size(); i++) {
                String[] s = results.get(i).toLowerCase().split("IOS_AC_CN".toLowerCase());
                bean.getAttackBeanList().get(i).setAttackSuccess(Boolean.parseBoolean(s[0]));
                if (Boolean.parseBoolean(s[0])) {
                    bean.setReDoS(true);
                }
                bean.getAttackBeanList().get(i).setRepeatTimes(Integer.parseInt(s[1]));
                bean.getAttackBeanList().get(i).setAttackTime(Integer.parseInt(s[2]));
            }
            return bean;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            FileUtils.deleteQuietly(new File("js/" + name));
            FileUtils.deleteQuietly(new File("js/" + name.replace(".txt", "_result.txt")));
        }
        return bean;
    }

    /**
     * 筛选肯定不是redos的正则
     *
     * @param regex
     * @return
     */
    public static boolean mustBeNoReDoS(String regex) {
        Matcher matcher = Pattern.compile(EXTENDED_COUNTING).matcher(regex);
        return !matcher.find();
    }
}
