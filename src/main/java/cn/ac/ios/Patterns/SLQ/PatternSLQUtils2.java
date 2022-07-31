package cn.ac.ios.Patterns.SLQ;

import cn.ac.ios.TreeNode.TreeNode;
import cn.ac.ios.Bean.*;
import cn.ac.ios.Utils.Constant;
import cn.ac.ios.Utils.SplitRegexUtils;

import java.util.*;

import static cn.ac.ios.Patterns.SLQ.SLQUtils.*;
import static cn.ac.ios.TreeNode.Utils.createReDoSTree;
import static cn.ac.ios.TreeNode.Utils.rewriteRegex;
import static cn.ac.ios.Utils.FlagsUtils.*;
import static cn.ac.ios.Utils.GenMatchStringUtils.getExampleByDkBricsAutomaton2;
import static cn.ac.ios.Utils.GenMatchStringUtils.getTranslateRegexForAssertionsList;
import static cn.ac.ios.Utils.NegateUtils.*;
import static cn.ac.ios.Utils.RegexUtils.*;

/**
 * @author pqc
 */
public class PatternSLQUtils2 {

    public static void main(String[] args) throws InterruptedException {
        String regex = "/(<object\\s*[^>]*\\s*id\\s*=\\s*(?P<m3>\\x22|\\x27|)(?P<id1>.+?)(?P=m3)(\\s|>)[^>]*\\s*classid\\s*=\\s*(?P<q6>\\x22|\\x27|)\\s*clsid\\s*\\x3a\\s*{?\\s*FAF02D9B-963D-43D8-91A6-E71383503FDA\\s*}?\\s*(?P=q6)(\\s|>).*(?P=id1)\\s*\\.\\s*(Anomaly)|<object\\s*[^>]*\\s*classid\\s*=\\s*(?P<q7>\\x22|\\x27|)\\s*clsid\\s*\\x3a\\s*{?\\s*FAF02D9B-963D-43D8-91A6-E71383503FDA\\s*}?\\s*(?P=q7)(\\s|>)[^>]*\\s*id\\s*=\\s*(?P<m4>\\x22|\\x27|)(?P<id2>.+?)(?P=m4)(\\s|>).*(?P=id2)\\s*\\.\\s*(Anomaly))\\s*=/Osi";
        regex = "[ \\t]*?(?=\\r?\\n)";
        getSLQReDoSBean(regex, "java");
    }


    /**
     * 预处理
     *
     * @param regex
     * @return
     * @throws InterruptedException
     */
    private static TreeNode getReDoSTree(String regex, String language) throws InterruptedException {
        language = language.toLowerCase();

        // 最开头的预处理
        regex = rewriteRegex(regex);

        // todo 这种替换不支持 \n ,待处理
        regex = regex.replace("[\\s\\S]", ".");
        regex = regex.replace("[\\w\\W]", ".");
        regex = regex.replace("[\\d\\D]", ".");
        regex = regex.replace("[\\S\\s]", ".");
        regex = regex.replace("[\\W\\w]", ".");
        regex = regex.replace("[\\D\\d]", ".");

        regex = reduceLocalFlags(regex);
        regex = removeAnnotationByFlagX(regex);
        regex = processLocalFlag(regex);
        regex = replaceLocalFlagGM(regex);

        // 建树
        TreeNode ReDoSTree = createReDoSTree(regex);

        // 删除注释
        ReDoSTree.deleteAnnotation();

        // 转换[\w-.] -> [\w\-.] 而 [a-z]保留 为了regexlib
        ReDoSTree.rewriteIllegalBarSymbol();

        if (language.equals("java")) {
            // 处理java中奇奇怪怪的character_class 及 交集问题
            ReDoSTree.dealWithCharacterClassInJava();
        } else if (language.equals("python")) {
            // 处理python中{,4}的问题
            ReDoSTree.dealWithUnusualQuantifierInPython();
        }

        // 将possessive和lazy匹配转换为对应的greedy匹配
        ReDoSTree.transNonGreedyQuantifier();

        // 去group name
        ReDoSTree.deleteGroupName();

        // 针对snort数据集中出现的{?写法 需要在{前加\ 暂不知是否还有其他需要加斜杠的
        ReDoSTree.addBackslashBeforeSomeCharacters();

        // 将方括号中的\0~\777重写为\u0000~\u0777
        ReDoSTree.rewriteUnicodeNumberInBracketNode();

        // 将方括号中的\b删除 因为方括号中的\b表示退格符
        ReDoSTree.reWriteBackspace();

        // 优化方括号结点, 将内部重复的字符删掉
        // 这里假设结点内部不会嵌套方括号结点/补结点
        ReDoSTree.optimizeBracketNode();

        // 处理\x{....} \xff
        ReDoSTree.escapeHexadecimal();
        // 删除Flags
        ReDoSTree = getNodeByRemoveRegExpFlag(ReDoSTree);

        ReDoSTree = getNodeByRemoveLocalFlag(ReDoSTree);

        // 重写反向引用
        ReDoSTree.rewriteBackreferences();

        removeNegateSymbol(ReDoSTree, Constant.SimplyLevel.HIGH);

        // 新版重写空串
        ReDoSTree = removeBlankStr(ReDoSTree);

        // 重写反向引用后 删除NonCapturingGroupFlag ?:
        ReDoSTree.deleteNonCapturingGroupFlag();

        return ReDoSTree;
    }


    /**
     * 预处理
     *
     * @param regex
     * @return
     * @throws InterruptedException
     */
    private static TreeNode translateRegex(String regex) throws InterruptedException {
        // 建树
        TreeNode ReDoSTree = createReDoSTree(regex);

        setZeroWidthAssertion(ReDoSTree);

        return ReDoSTree;
    }

    public static ReDoSBean getSLQReDoSBean(String regex, String language) {
        ReDoSBean bean = new ReDoSBean();
        try {
            TreeNode root = getReDoSTree(regex, language);
            bean = PatternSLQUtils2.getSLQReDoSBeanHelper(root, regex);
        } catch (InterruptedException e) {
            bean.setReDoS(false);
        } catch (Exception e) {
            bean.setMessage("PARSE ERROR");
            bean.setReDoS(false);
        }
        return bean;
    }

    private static ReDoSBean getSLQReDoSBeanHelper(TreeNode root, String regex) {
        ReDoSBean bean = new ReDoSBean();
        ArrayList<AttackBean> list = getSLQCondition(root, regex);
        list.sort(Comparator.comparingInt(o -> o.getInfix().length()));
        bean.getAttackBeanList().addAll(list);
        return bean;
    }


    /**
     * @param root
     * @param regex
     * @return
     */
    private static ArrayList<AttackBean> getSLQCondition(TreeNode root, String regex) {
        ArrayList<AttackBean> list = new ArrayList<>();
        ArrayList<TreeNode> nodes = getAllCountingNode(root);
        for (TreeNode node : nodes) {
            String preRegex = SplitRegexUtils.getR0(root, node);
            String suffixRegex = SplitRegexUtils.getR4(root, node);
            if (getParOrNode(node) != null) {
                String orRegex = getParOrNode(node).getData();
            }
            String infixRegex = node.getData();
            if (suffixRegex.length() == 0) {
                suffixRegex = infixRegex;
            }
            try {
                String attackInfix;
                TreeNode pre = createReDoSTree(preRegex);
                if (preRegex.length() == 0 || isCanEmptyNode(pre)) {
                    attackInfix = getMatchString(infixRegex, suffixRegex);
                } else {
                    attackInfix = getMatchString(preRegex, infixRegex, suffixRegex);
                }

                if (attackInfix == null || attackInfix.length() == 0) {
                    continue;
                }
                String attackSuffix = getNoMatchString(suffixRegex);
                if (attackSuffix == null || attackSuffix.length() == 0) {
                    attackSuffix = getNoMatchString(infixRegex);
                }

                if (attackSuffix == null || attackSuffix.length() == 0) {
                    continue;
                }

                AttackBean attackBean = new AttackBean();
                attackBean.setPrefix("");
                attackBean.setInfix(attackInfix);
                attackBean.setSuffix(attackSuffix);
                attackBean.initType(AttackType.POLYNOMIAL);
                attackBean.setPatternType(PatternType.SLQ2);
                list.add(attackBean);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return list;
    }

    private static String getMatchString(String infixRegex, String suffixRegex) {
        String regex = infixRegex;
        if (suffixRegex.length() != 0) {
            regex = "(" + infixRegex + ")＆(～(" + suffixRegex + "))";
        }
        try {
            return getMatchString(regex);
        } catch (InterruptedException e) {
            return "";
        }
    }

    private static String getMatchString(String preRegex, String infixRegex, String suffixRegex) {
        try {
            String attackInfix;
            if (suffixRegex.length() != 0) {
                String regex = "(" + preRegex + ".*)＆" + "(" + infixRegex + ")＆(～(" + suffixRegex + "))";
                attackInfix = getMatchString(regex);
                if (attackInfix == null || attackInfix.length() == 0) {
                    regex = "(.*" + preRegex + ")＆" + "(" + infixRegex + ")＆(～(" + suffixRegex + "))";
                    attackInfix = getMatchString(regex);
                }
                if (attackInfix == null || attackInfix.length() == 0) {
                    regex = "(.*" + preRegex + ".*)＆" + "(" + infixRegex + ")＆(～(" + suffixRegex + "))";
                    attackInfix = getMatchString(regex);
                }
            } else {
                String regex = "(" + preRegex + ".*)＆" + "(" + infixRegex + ")";
                attackInfix = getMatchString(regex);
                if (attackInfix == null || attackInfix.length() == 0) {
                    regex = "(.*" + preRegex + ")＆" + "(" + infixRegex + ")";
                    attackInfix = getMatchString(regex);
                }
                if (attackInfix == null || attackInfix.length() == 0) {
                    regex = "(.*" + preRegex + ".*)＆" + "(" + infixRegex + ")";
                    attackInfix = getMatchString(regex);
                }
            }
            return attackInfix;
        } catch (InterruptedException e) {
            return "";
        }
    }


    public static String getMatchString(String regex) throws InterruptedException {
        TreeNode node = createReDoSTree(regex);
        List<String> innerTrans = getTranslateRegexForAssertionsList(node);
        List<String> regexList1 = new ArrayList<>(innerTrans);
        return getExampleByDkBricsAutomaton2(regexList1, 1);
    }

    public static String getNoMatchString(String regex) throws InterruptedException {
        TreeNode node = createReDoSTree("～(" + regex + ")");
        List<String> innerTrans = getTranslateRegexForAssertionsList(node);
        List<String> regexList1 = new ArrayList<>(innerTrans);
        return getExampleByDkBricsAutomaton2(regexList1, 1);
    }

}
