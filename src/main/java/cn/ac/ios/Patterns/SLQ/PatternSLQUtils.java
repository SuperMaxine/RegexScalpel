package cn.ac.ios.Patterns.SLQ;

import cn.ac.ios.TreeNode.TreeNode;
import cn.ac.ios.Bean.*;
import cn.ac.ios.Utils.Constant;

import java.util.*;

import static cn.ac.ios.Patterns.SLQ.SLQUtils.*;
import static cn.ac.ios.TreeNode.Utils.createReDoSTree;
import static cn.ac.ios.TreeNode.Utils.rewriteRegex;
import static cn.ac.ios.Utils.FlagsUtils.*;
import static cn.ac.ios.Utils.NegateUtils.*;
import static cn.ac.ios.Utils.RegexUtils.*;
import static cn.ac.ios.Utils.SplitRegexUtils.getR4;

/**
 * @author pqc
 */
public class PatternSLQUtils {

    public static void main(String[] args) throws InterruptedException {
        String regex = "(a+)(d(b+[(](a|b+|c{1,})+)|([^abc]+))";
//        regex = "((()+)|([^abc]+))";
        TreeNode root = getReDoSTree(regex, "java");
        ArrayList<TreeNode> nodes = getAllCountingNode(root);

        for (TreeNode node : nodes) {
            ArrayList<String> strings = splitTreeByNode(root, node);
            System.out.println(node.getData());
            System.out.println(getR4(root, node));
            System.out.println(strings.get(1));
//            for (String str : strings) {
//                System.out.println(str);
//            }
            System.out.println("--------------");
        }
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
        TreeNode ReDoSTree = createReDoSTree(regex, language);

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

        // 处理特殊斜杠字符 根据不同的语言
        ReDoSTree.rewriteSpecialBackslashCharacterForDifferentLanguage(language);

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

    public static ReDoSBean getSLQReDoSBean(String regex, String language) {
        ReDoSBean bean = new ReDoSBean();
        try {
            TreeNode root = getReDoSTree(regex, language);
            bean = PatternSLQUtils.getSLQReDoSBeanHelper(root, regex, language);
        } catch (InterruptedException e) {
            bean.setReDoS(false);
        } catch (Exception e) {
            bean.setMessage("PARSE ERROR");
            bean.setReDoS(false);
        }
        return bean;
    }

    public static ReDoSBean getSLQReDoSBeanHelper(TreeNode root, String regex, String language) {
        ReDoSBean bean = new ReDoSBean();
        ArrayList<AttackBean> list1 = getSLQConditionOne(root, regex);
        ArrayList<AttackBean> list2 = getSLQConditionTwo(root, regex);
        ArrayList<AttackBean> beans = new ArrayList<>();
        for (AttackBean attackBean : list2) {
            AttackBean item = new AttackBean();
            item.setPrefix("");
            item.setInfix(attackBean.getPrefix() + attackBean.getInfix());
            item.setSuffix(attackBean.getSuffix());
            item.initType(AttackType.POLYNOMIAL);
            item.setPatternType(attackBean.getPatternType());
            beans.add(item);
        }
        list1.addAll(beans);
        list1.addAll(list2);//todo slq2 应该没有前缀
        ArrayList<AttackBean> list3 = getSLQConditionThree(root, regex);
        if (list3.size() < 100) {
            list1.addAll(list3);
        }
        ArrayList<AttackBean> list4 = getSLQConditionSp(root, regex);
        list1.addAll(list4);
        list1.sort(Comparator.comparingInt(o -> o.getInfix().length()));
        list1.addAll(0, PatternSLQUtils2.getSLQReDoSBean(regex, language).getAttackBeanList());
        bean.getAttackBeanList().addAll(list1);
        return bean;
    }


    /**
     * @param root
     * @param regex
     * @return
     */
    private static ArrayList<AttackBean> getSLQCondition(TreeNode root, String regex) {
        ArrayList<TreeNode> nodes = getAllCountingNode(root);
        for (TreeNode node : nodes) {
            ArrayList<String> strings = splitTreeByNode(root, node);
            String preRegex = strings.get(0);
            String suffixRegex = strings.get(1);
            String orRegex = strings.get(2);
        }
        return null;
    }

    /**
     * 处理特殊正则 ^\\s+|\\s+$
     *
     * @param root
     * @param regex
     * @return
     */
    public static ArrayList<AttackBean> getSLQConditionSp(TreeNode root, String regex) {
        ArrayList<AttackBean> list = new ArrayList<>();
        if (regex.startsWith("^") && regex.endsWith("$") && isOrNode(root)) {
            root = getGroupSubNode(root);
            if (root.getChild(0).getData().equals(root.getChild(2).getData())) {
                list = getSLQConditionOne(root.getChild(0), root.getChild(0).getData());
                for (AttackBean attackBean : list) {
                    attackBean.setPrefix(root.getChild(0).getNonMatchStr());
                }
            }
        }
        return list;
    }

    private static ArrayList<AttackBean> getSLQConditionThree(TreeNode root, String regex) {
        ArrayList<AttackBean> list = new ArrayList<>();
        Stack<TreeNode> stack = new Stack();
        stack.add(root);
        while (!stack.isEmpty()) {
            TreeNode node = stack.pop();
            if (isSLQThreeCountingNode(node)) {
                node = getGroupSubNode(node).getChild(0);
                ArrayList<String> arrayList = getMatchExamples(node);
                for (String str : arrayList) {
                    AttackBean attackBean = new AttackBean();
                    attackBean.setPrefix(root.getMatchStr(node));
                    attackBean.setSuffix(root.getNonMatchStr(node) + root.getNonMatchStr());
                    attackBean.setInfix(str);
                    attackBean.initType(AttackType.POLYNOMIAL);
                    attackBean.setPatternType(PatternType.SLQ_3);
                    list.add(attackBean);
                }
            }
            for (int i = node.getChildCount() - 1; i >= 0; i--) {
                stack.push(node.getChild(i));
            }
        }
        return list;
    }

    /**
     * SLQ 模式 ，条件一
     *
     * @param root
     * @param regex 暂时不用
     * @return 一组攻击串
     */
    @Deprecated
    private static ArrayList<AttackBean> getSLQConditionOne(TreeNode root, String regex) {
        ArrayList<AttackBean> list = new ArrayList<>();
        if (isGroupNode(root)) {
            return getSLQConditionOne(getGroupSubNode(root), getGroupSubNode(root).getData());
        }
        if (isOrNode(root)) {
            root = getGroupSubNode(root);
            for (TreeNode child : root.getChildList()) {
                if (!child.getData().equals("|")) {
                    list.addAll(getSLQConditionOne(child, child.getData()));
                }
            }
            return list;
        }
        ArrayList<Pair<String, String>> pairArrayList = getFirstAndCountingNode(root);
        if (pairArrayList == null) {
            return list;
        }
        for (Pair<String, String> pair : pairArrayList) {
            String repeat = pair.getKey();
            if (repeat.length() == 0) {
                continue;
            }
            String suffix = pair.getValue();
            AttackBean attackBean = new AttackBean();
            attackBean.setPrefix("");
            attackBean.setInfix(repeat);
            attackBean.setSuffix(suffix);
            attackBean.initType(AttackType.POLYNOMIAL);
            attackBean.setPatternType(PatternType.SLQ_1);
            list.add(attackBean);
        }
        return list;
    }


    /**
     * SLQ模式,条件一，找到第一个节点，如果是集合节点，则生成对应攻击串
     *
     * @param root
     * @return 一组pair，包含infix和suffix
     * 支持潜逃
     */
    @Deprecated
    private static ArrayList<Pair<String, String>> getFirstAndCountingNode(TreeNode root) {
        if (isGroupNode(root)) {
            return getFirstAndCountingNode(getGroupSubNode(root));
        }
        if (isOrNode(root)) {
            root = getGroupSubNode(root);
            ArrayList<Pair<String, String>> list = new ArrayList<>();
            for (TreeNode child : root.getChildList()) {
                if (!"|".equals(child.getData())) {
                    list.addAll(getFirstAndCountingNode(child));
                }
            }
            return list;
        }
        if (root.getChildList().isEmpty()) {
            return new ArrayList<>();
        }
        if (isSLQCountingNode(root)) {
            Pair<String, String> pair;
            String repeat = root.getMatchStrWithCounting();
            pair = new Pair<>(repeat, "");
            ArrayList<Pair<String, String>> list = new ArrayList<>();
            list.add(pair);
            return list;
        }
        TreeNode node = root.getChild(0);
        while (!node.isLeaf() && node.getLastChild().getData().equals("?") && getFirstAndCountingNode(node).isEmpty()) {
            node = node.getNextNode();
        }
        if (isGroupNode(node)) {
            node = getGroupSubNode(node);
            StringBuilder suffix = new StringBuilder();
            ArrayList<Pair<String, String>> list = new ArrayList<>();
            ArrayList<Pair<String, String>> pairArrayList = getFirstAndCountingNode(node);
            if (pairArrayList != null) {
                if (suffix.length() == 0) {
                    for (int i = 1; i < root.getChildCount(); i++) {
                        String data = root.getChild(i).getNonMatchStr();
                        if (data.length() > 0) {
                            suffix.append(data);
                            break;
                        }
                    }
                    if (suffix.length() == 0) {
                        suffix.append(root.getNonMatchStr());
                    }
                }
                for (Pair<String, String> pair : pairArrayList) {
                    list.add(new Pair<>(pair.getKey(), pair.getValue() + suffix));
                }
            }
            return list;
        }
        if (isOrNode(node)) {
            node = getGroupSubNode(node);
            StringBuilder suffix = new StringBuilder();
            ArrayList<Pair<String, String>> list = new ArrayList<>();
            for (TreeNode child : node.getChildList()) {
                if (!"|".equals(child.getData())) {
                    if (isSLQCountingNode(child)) {
                        String repeat = child.getMatchStrWithCounting();
                        if (suffix.length() == 0) {
                            for (int i = 1; i < root.getChildCount(); i++) {
                                String data = root.getChild(i).getNonMatchStr();
                                if (data.length() > 0) {
                                    suffix.append(data);
                                    break;
                                }
                            }
                            if (suffix.length() == 0) {
                                suffix.append(root.getNonMatchStr());
                            }
                        }
                        Pair<String, String> pair = new Pair<>(repeat, suffix.toString());
                        list.add(pair);
                    } else {
                        ArrayList<Pair<String, String>> pairArrayList = getFirstAndCountingNode(child);
                        if (pairArrayList != null) {
                            if (suffix.length() == 0) {
                                for (int i = 1; i < root.getChildCount(); i++) {
                                    String data = root.getChild(i).getNonMatchStr();
                                    if (data.length() > 0) {
                                        suffix.append(data);
                                        break;
                                    }
                                }
                                if (suffix.length() == 0) {
                                    suffix.append(root.getNonMatchStr());
                                }
                            }
                            for (Pair<String, String> pair : pairArrayList) {
                                list.add(new Pair<>(pair.getKey(), pair.getValue() + suffix));
                            }
                        }
                    }
                }
            }
            return list;
        } else {
            if (isSLQCountingNode(node)) {
                Pair<String, String> pair;
                String repeat = node.getMatchStrWithCounting();
                StringBuilder suffix = new StringBuilder();
                for (int i = 1; i < root.getChildCount(); i++) {
                    String data = root.getChild(i).getNonMatchStr();
                    if (data.length() > 0) {
                        suffix.append(data);
                        break;
                    }
                }
                if (suffix.length() == 0) {
                    suffix.append(root.getNonMatchStr());
                }
                pair = new Pair<>(repeat, suffix.toString());
                ArrayList<Pair<String, String>> list = new ArrayList<>();
                list.add(pair);
                return list;
            }
        }
        return new ArrayList<>();
    }

    /**
     * SLQ模式，条件二，对应的攻击串
     *
     * @return 多个攻击串
     */
    public static ArrayList<AttackBean> getSLQConditionTwo(TreeNode ReDoSTree, String regex) {
        ArrayList<AttackBean> list = new ArrayList<>();
        List<TreeNode> treeNodeList = ReDoSTree.getChildList();
        ArrayList<Integer> dotList = new ArrayList<>();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < treeNodeList.size(); i++) {
            if (treeNodeList.get(i).getData().length() >= 3) {
                ArrayList<AttackBean> sublist = getSLQConditionTwo(treeNodeList.get(i), treeNodeList.get(i).getData());
                for (AttackBean attackBean : sublist) {
                    attackBean.setPrefix(attackBean.getPrefix() + stringBuilder.toString());
                    if (i > 1) {
                        attackBean.setSuffix(treeNodeList.get(i - 1).getNonMatchStr() + attackBean.getSuffix());
                    }
                }
                list.addAll(sublist);
            }
            stringBuilder.append(treeNodeList.get(i).getMatchStr());
            if (isSetRepeatNode(treeNodeList.get(i))) {
                dotList.add(i);
            } else if (isSingleCountingNode(treeNodeList.get(i))) {
                dotList.add(i);
            } else if (isGeneralizedCountingNodeWithMaxNumGreaterThanOne(treeNodeList.get(i))) {
                dotList.add(i);
            }
        }

        for (Integer index : dotList) {
            StringBuilder repeat = new StringBuilder();
            for (int i = 0; i < index; i++) {
                repeat.append(treeNodeList.get(i).getMatchStrWithCounting());
            }
            if (index == 0) {
                repeat.append(treeNodeList.get(0).getMatchStrWithCounting());
            }
            if (repeat.length() == 0) {
                continue;
            }

            StringBuilder suffix = new StringBuilder();
            for (int i = index; i < treeNodeList.size(); i++) {
                suffix.append(treeNodeList.get(i).getNonMatchStr());
                if (!suffix.toString().isEmpty()) {
                    break;
                }
            }
            if (index > 1) {
                suffix.append(treeNodeList.get(index - 1).getNonMatchStr());
            }
            AttackBean attackBean = new AttackBean();
            attackBean.setPrefix("");
            attackBean.setInfix(repeat.toString());
            attackBean.setSuffix(suffix.toString());
            attackBean.initType(AttackType.POLYNOMIAL);
            attackBean.setPatternType(PatternType.SLQ_2);
            list.add(attackBean);
            if (suffix.toString().contains(" ")) {
                attackBean = new AttackBean();
                attackBean.setPrefix("");
                attackBean.setInfix(repeat.toString());
                attackBean.setSuffix(suffix.toString().replace(" ", ""));
                attackBean.initType(AttackType.POLYNOMIAL);
                attackBean.setPatternType(PatternType.SLQ_2);
                list.add(attackBean);
            }
        }
        return list;
    }

}
