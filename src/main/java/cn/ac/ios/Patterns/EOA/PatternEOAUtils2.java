package cn.ac.ios.Patterns.EOA;

import cn.ac.ios.TreeNode.TreeNode;
import cn.ac.ios.Bean.AttackBean;
import cn.ac.ios.Bean.AttackType;
import cn.ac.ios.Bean.ReDoSBean;
import cn.ac.ios.Utils.Constant;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.RegExp;

import java.util.*;

import static cn.ac.ios.TreeNode.Utils.*;
import static cn.ac.ios.Utils.BracketUtils.isBracketsNode;
import static cn.ac.ios.Utils.DkBricsAutomatonUtils.*;
import static cn.ac.ios.Utils.FlagsUtils.*;
import static cn.ac.ios.Utils.FlagsUtils.getNodeByRemoveLocalFlag;
import static cn.ac.ios.Utils.NegateUtils.refactorAssertPattern;
import static cn.ac.ios.Utils.NegateUtils.removeNegateSymbol;
import static cn.ac.ios.Utils.RegexUtils.*;
import static cn.ac.ios.Utils.RegexUtils.getGroupSubNode;

public class PatternEOAUtils2 {
    public static TreeNode getRedosTree(String regex) throws InterruptedException {
        // 最开头的预处理
        regex = rewriteRegex(regex);
        regex = reduceLocalFlags(regex);
        regex = removeAnnotationByFlagX(regex);
        regex = processLocalFlag(regex);
        regex = replaceLocalFlagGM(regex);
        // 去group name
        regex = deleteGroupName(regex);

        // 建树
        TreeNode newlyttree = createReDoSTree(regex);

        // 将方括号中的\0~\777重写为\u0000~\u0777
        newlyttree.rewriteUnicodeNumberInBracketNode();

        // 将方括号中的\b删除 因为方括号中的\b表示退格符
        newlyttree.reWriteBackspace();

        // 转换[\w-.] -> [\w\-.] 而 [a-z]保留 为了regexlib
        newlyttree.rewriteIllegalBarSymbol();

        newlyttree = refactorAssertPattern(newlyttree);

        // 处理\x{....} \xff
        newlyttree.escapeHexadecimal();
        // 删除Flags
        newlyttree = getNodeByRemoveRegExpFlag(newlyttree);

        newlyttree = getNodeByRemoveLocalFlag(newlyttree);

        // 使用重写后的去首尾^$
        newlyttree.deleteCaretAndDollarSymbols();

//        regex = rewriteEmptyString(newlyttree.getData());
//
//        if (!regex.equals(newlyttree.getData())) {
//            newlyttree = createnewlyttree(regex);
//        }

        // 新版重写空串
        newlyttree = removeBlankStr(newlyttree);

        // 重写反向引用
        newlyttree.rewriteBackreferences();

        // 重写反向引用后 删除NonCapturingGroupFlag ?:
        newlyttree.deleteNonCapturingGroupFlag();

        // 获取后缀
//        String suffix = getSuffixByNegateNode(newlyttree);
        // 去补
        removeNegateSymbol(newlyttree, Constant.SimplyLevel.HIGH);

//        newlyttree = refactorToDot(newlyttree);

//        newlyttree = removeGroup(newlyttree);

//        return new Pair<>(newlyttree, suffix);

        // 计算所有结点的first last followLast nullable flexible
        newlyttree.calculateFiveAttributesNullableAndFirstAndLastAndFlexibleAndFollowLast();

        return newlyttree;
    }

    // 生成中缀串forPOA
    private static String generateInfixStringForPOA(String regex1, String regex2, String regex3) throws InterruptedException {
        List<String> regexList1 = new ArrayList<>();
        regexList1.add(regex1);
        regexList1.add(regex2 + regex3);
        regexList1.add(regex3);
        return getExampleByDkBricsAutomaton(regexList1);



//        String regex = "1&2";
//
//        regex = reWriteMetaEscape("(" + regex1 + ")＆(" + regex2 + regex3 +")＆(" + regex3 + ")") + "＆(.+)";
//
//
////        // 这里的reWriteMetaEscape就是要写在外面 e.g.     .+\.{a-z}+     regex1 = .+      regex2 = \.{a-z}+   写在里面regex1.getLetterSet就是!了
////        if (regex2.equals("")) {
////            regex = reWriteMetaEscape("(" + regex1 + ")＆(" + regex3 + ")") + "＆(.+)"; // 注意这里＆不是& 这样做是为了防&被加方括号
////        } else {
////            regex = reWriteMetaEscape("(" + regex1 + ")＆(" + regex2 + ")＆(" + regex3 + ")") + "＆(.+)"; // 注意这里＆不是& 这样做是为了防&被加方括号
////        }
//        regex = reductSpecailStringForDkBricsAutomaton(regex);
////        System.out.println(regex);
////        regex = regex + "&(.{" + counting + "})";
//        RegExp regExp = new RegExp(regex);
//        Automaton automaton = regExp.toAutomaton(false);    // 这里要加第二个参数minimize: false 这样就是nfa了 比dfa快
//        String infix = automaton.getShortestExample(true);
//        return infix;
    }

    // 判断treeNode的父节点们的counting值都＜1
    private static boolean isAllParentCountingLessOrEqualToOne(TreeNode treeNode) {
        TreeNode parent = treeNode.getParent();
        while (parent != null) {
            if (isGeneralizedCountingNodeWithMaxNumGreaterThanOne(parent)) return false;
            parent = parent.getParent();
        }
        return true;
    }

    // 截取两个counting结点之间的正则 不包含两端 输入中left是左counting结点 right是右counting结点
    public static String getR2(TreeNode root, TreeNode left, TreeNode right) {
        root = getGroupSubNode(root);
        TreeNode left2 = left;      // left的备份指针
        TreeNode right2 = right;    // right的备份指针

        String leftRegex = left.getData();
        StringBuilder midRegex = new StringBuilder();
        StringBuilder rightRegex = new StringBuilder(right.getData());
        boolean start = false;
        if (left == root) return midRegex.toString();
        while (left.getParent() != root) {
            TreeNode parent = left.getParent();
            if (parent != null && !isGroupNode(parent)) {
                if (isOrNode(parent)) {
//                    if (!midRegex.toString().endsWith(".*")) {
//                        midRegex.append(".*");
//                    }
                } else {
                    for (int i = 0; i < parent.getChildCount(); i++) {
                        if (start) {
                            if (!parent.getChild(i).isNowNodeChildOrGrandchild(left2) && parent.getChild(i) != left2
                                    && !parent.getChild(i).isNowNodeChildOrGrandchild(right2) && parent.getChild(i) != right2
                                    && !isQuantifierNode(parent.getChild(i)))
                                midRegex.append(parent.getChild(i).getData());
                        }
                        if (parent.getChild(i).isNowNodeChildOrGrandchild(right2) || parent.getChild(i) == right2) {
                            start = false;
                        }
//                        if (parent.getChild(i) == right) {
                        if (parent.getChild(i) == left2) {
                            start = true;
                        }
                    }
                }
            }
            left = parent;
        }

        if (right == root) return midRegex.toString();
        while (right.getParent() != root) {
            TreeNode parent = right.getParent();
            if (parent != null && !isGroupNode(parent)) {
                if (isOrNode(parent)) {
//                    if (!rightRegex.toString().startsWith(".*")) {
//                        rightRegex.insert(0, ".*");
//                    }
                } else {
                    for (int i = 0; i < parent.getChildCount(); i++) {
                        if (parent.getChild(i) == right || parent.getChild(i).isNowNodeChildOrGrandchild(left2) || parent.getChild(i) == left2) {
                            break;
                        } else {
//                            rightRegex.insert(0, parent.getChild(i).getData());
                            if (!parent.getChild(i).isNowNodeChildOrGrandchild(left2) && parent.getChild(i) != left2)
//                                midRegex.insert(0, parent.getChild(i).getData());
                                midRegex.append(parent.getChild(i).getData());
                        }
                    }
                }
            }
            right = parent;
        }

        StringBuilder midRegex2 = new StringBuilder();
        start = false;
        for (int i = 0; i < root.getChildCount(); i++) {
            TreeNode child = root.getChild(i);
            if (child == right) {
                break;
            }
            if (start) {
                if (!isQuantifierNode(child))
                    midRegex2.append(child.getData());
            }
            if (child == left) {
                start = true;
            }
        }

        return midRegex2.toString() + midRegex.toString();


//        System.out.println("---");
//        System.out.println(leftRegex);
//        System.out.println(midRegex);
//        System.out.println(rightRegex);
//        System.out.println("---");
    }


    public static String getR0(TreeNode root, TreeNode left) {
        root = getGroupSubNode(root);
        String leftRegex = left.getData();
        StringBuilder midRegex = new StringBuilder();
        boolean start = false;
        if (left == root) return "";
        while (left.getParent() != root) {
            TreeNode parent = left.getParent();
            if (parent != null && !isGroupNode(parent)) {
                if (isOrNode(parent)) {

                } else {
                    start = false;
                    for (int i = parent.getChildCount() - 1; i >= 0; i--) {
                        if (start) {
//                            midRegex.append(parent.getChild(i).getData());
                            if (!parent.getChild(i).isNowNodeChildOrGrandchild(left) && parent.getChild(i) != left &&
//                                    !parent.getChild(i).isNowNodeChildOrGrandchild(right) && parent.getChild(i) != right &&
                                        !isQuantifierNode(parent.getChild(i)))
//                                midRegex.append(parent.getChild(i).getData());
                                midRegex.insert(0, parent.getChild(i).getData());
                        }
                        if (parent.getChild(i) == left) {
                            start = true;
                        }
                    }
                }
            }
            left = parent;
        }

        if (! isOrNode(root)) {
            start = false;
            for (int i = root.getChildCount() - 1; i >= 0; i--) {
                TreeNode child = root.getChild(i);
//            if (child == left) {
//                break;
//            }
                if (start) {
                    if (!isQuantifierNode(child))
//                    midRegex.append(child.getData());
                        midRegex.insert(0, child.getData());
                }
                if (child == left) {
                    start = true;
                }
            }
        }

//        System.out.println("---");
//        System.out.println(leftRegex);
//        System.out.println(midRegex);
////        System.out.println(rightRegex);
//        System.out.println("---");


        return midRegex.toString();

    }

    public static String getR4(TreeNode root, TreeNode right) {
        root = getGroupSubNode(root);
//        String leftRegex = left.getData();
        StringBuilder midRegex = new StringBuilder();
        StringBuilder rightRegex = new StringBuilder(right.getData());
        boolean start = false;
//        while (left.getParent() != root) {
//            TreeNode parent = left.getParent();
//            if (parent != null && !isGroupNode(parent)) {
//                if (isOrNode(parent)) {
////                    if (!midRegex.toString().endsWith(".*")) {
////                        midRegex.append(".*");
////                    }
//                } else {
//                    for (int i = 0; i < parent.getChildCount(); i++) {
//                        if (start) {
//                            midRegex.append(parent.getChild(i).getData());
//                        }
////                        if (parent.getChild(i) == right) {
//                        if (parent.getChild(i) == left) {
//                            start = true;
//                        }
//                    }
//                }
//            }
//            left = parent;
//        }

        if (right == root) return "";
        while (right.getParent() != root) {
            TreeNode parent = right.getParent();
            if (parent != null && !isGroupNode(parent)) {
                if (isOrNode(parent)) {
//                    if (!rightRegex.toString().startsWith(".*")) {
//                        rightRegex.insert(0, ".*");
//                    }
                } else {
                    start = false;
                    for (int i = 0; i < parent.getChildCount(); i++) {
//                        if (parent.getChild(i) == right) {
//                            break;
//                        } else {
////                            rightRegex.insert(0, parent.getChild(i).getData());
//                            midRegex.insert(0, parent.getChild(i).getData());
//                        }

                        if (start) {
                            if (
//                                !parent.getChild(i).isNowNodeChildOrGrandchild(left) && parent.getChild(i) != left &&
                                !parent.getChild(i).isNowNodeChildOrGrandchild(right) && parent.getChild(i) != right
                                    && !isQuantifierNode(parent.getChild(i)))
                                midRegex.append(parent.getChild(i).getData());
                        }
//                        if (parent.getChild(i) == right) {
                        if (parent.getChild(i) == right) {
                            start = true;
                        }
                    }
                }
            }
            right = parent;
        }

        if (! isOrNode(root)) {
            start = false;
            for (int i = 0; i < root.getChildCount(); i++) {
                TreeNode child = root.getChild(i);
//            if (child == right) {
//                break;
//            }
                if (start) {
                    if (!isQuantifierNode(child))
                        midRegex.append(child.getData());
                }
                if (child == right) {
                    start = true;
                }
            }
        }
        return midRegex.toString();

//        System.out.println("---");
//        System.out.println(leftRegex);
//        System.out.println(midRegex);
//        System.out.println(rightRegex);
//        System.out.println("---");
    }

    @Deprecated
    // 截取两个counting结点在第二个counting之后的正则 不包含第二个正则
    private static String getR4(TreeNode root, TreeNode left, TreeNode right) {
        String leftRegex = left.getData();
        StringBuilder midRegex = new StringBuilder();
        StringBuilder rightRegex = new StringBuilder(right.getData());
        boolean start = false;
//        while (left.getParent() != root) {
//            TreeNode parent = left.getParent();
//            if (parent != null && !isGroupNode(parent)) {
//                if (isOrNode(parent)) {
////                    if (!midRegex.toString().endsWith(".*")) {
////                        midRegex.append(".*");
////                    }
//                } else {
//                    for (int i = 0; i < parent.getChildCount(); i++) {
//                        if (start) {
//                            midRegex.append(parent.getChild(i).getData());
//                        }
////                        if (parent.getChild(i) == right) {
//                        if (parent.getChild(i) == left) {
//                            start = true;
//                        }
//                    }
//                }
//            }
//            left = parent;
//        }

        while (right.getParent() != root) {
            TreeNode parent = right.getParent();
            if (parent != null && !isGroupNode(parent)) {
                if (isOrNode(parent)) {
//                    if (!rightRegex.toString().startsWith(".*")) {
//                        rightRegex.insert(0, ".*");
//                    }
                } else {
                    start = false;
                    for (int i = 0; i < parent.getChildCount(); i++) {
//                        if (parent.getChild(i) == right) {
//                            break;
//                        } else {
////                            rightRegex.insert(0, parent.getChild(i).getData());
//                            midRegex.insert(0, parent.getChild(i).getData());
//                        }

                        if (start) {
                            if (!parent.getChild(i).isNowNodeChildOrGrandchild(left) && parent.getChild(i) != left
                                    && !parent.getChild(i).isNowNodeChildOrGrandchild(right) && parent.getChild(i) != right
                                    && !isQuantifierNode(parent.getChild(i)))
                                midRegex.append(parent.getChild(i).getData());
                        }
//                        if (parent.getChild(i) == right) {
                        if (parent.getChild(i) == right) {
                            start = true;
                        }
                    }
                }
            }
            right = parent;
        }

        start = false;
        for (int i = 0; i < root.getChildCount(); i++) {
            TreeNode child = root.getChild(i);
//            if (child == right) {
//                break;
//            }
            if (start) {
                if (!isQuantifierNode(child))
                    midRegex.append(child.getData());
            }
            if (child == right) {
                start = true;
            }
        }

        return midRegex.toString();

//        System.out.println("---");
//        System.out.println(leftRegex);
//        System.out.println(midRegex);
//        System.out.println(rightRegex);
//        System.out.println("---");
    }

    // 判断是POA还是EOA 对于(a*aa*c)*就是POA 对于(a*aa*c?)*就是EOA
    // 判断方法是 r4 ∩ r1 = ∅ 且 r4 ∩ r3 = ∅ 就是POA
    // 其中 r4 = c/c?     r1 = 第一个a*     r3 = 第二个a*
    private static boolean isPOAnotEOA(String r1, String r3, String r4) throws InterruptedException {
        if (r4.equals("")) return false;

        String regex = reWriteMetaEscape("(" + r4 + ")＆(" + r1 + ")",true);
        regex = reductSpecialStringForDkBricsAutomaton(regex);
        RegExp regExp = new RegExp(regex);
        Automaton automaton = regExp.toAutomaton(false);    // 这里要加第二个参数minimize: false 这样就是nfa了 比dfa快
        if (! automaton.isEmpty()) return false;

        regex = reWriteMetaEscape("(" + r4 + ")＆(" + r3 + ")", true);
        regex = reductSpecialStringForDkBricsAutomaton(regex);
        regExp = new RegExp(regex);
        automaton = regExp.toAutomaton(false);    // 这里要加第二个参数minimize: false 这样就是nfa了 比dfa快
        if (! automaton.isEmpty()) return false;

        return true;
    }

    private static ReDoSBean getEOARedosBeanHepler2(TreeNode root, String regex) {
        ReDoSBean bean = new ReDoSBean();
        ArrayList<AttackBean> attackBeanList = new ArrayList<>();
//        List<TreeNode> allPossibleChildren = root.getAllPossibleChildren();
        List<TreeNode> allPossibleChildren = root.getAllGeneralizedCountingWithMaxNumLeqOneNode();
        for (int i = 0; i < allPossibleChildren.size(); i++) {
            for (int j = i + 1; j < allPossibleChildren.size(); j++) {
                TreeNode child1 = allPossibleChildren.get(i);
                TreeNode child2 = allPossibleChildren.get(j);
                if (child1.isNowNodeChildOrGrandchild(child2) || child2.isNowNodeChildOrGrandchild(child1)) continue;
                // 获取最近的爹
                TreeNode nearestParent = getNearestParent(child1, child2);
                // 在最近的爹的基础上找最近的counting >1 的爹
                TreeNode specialParent = getTheNearestParentWithMaxNumGreaterThanOneGeneralizedCounting(nearestParent);
                // 外侧一定要有一个counting >1的爹
                if (specialParent == null) continue;
                // 最近的爹如果不是连接结点 则不是EOA
                if (! (!isOrNode(nearestParent) && !isBracketsNode(nearestParent) && !nearestParent.isLeaf() && !isGeneralizedCountingNode(nearestParent) && nearestParent.getChildCount() >= 2) ) {    // 不是是连接结点
                    continue;
                }

                // 判断是否满足条件1    beta1.followLast ∩ beta2.first ≠ ∅
                // 找到最近的爹下属孩子结点中包含child1的结点beta1, 包含child2的结点beta2
                int beta1Index = 0;
                for (; beta1Index < nearestParent.getChildCount(); beta1Index++) {
                    if (nearestParent.getChild(beta1Index).isNowNodeChildOrGrandchild(child1)) break;
                }
                int beta2Index = beta1Index + 1;
                for (; beta2Index < nearestParent.getChildCount(); beta2Index++) {
                    if (nearestParent.getChild(beta2Index).isNowNodeChildOrGrandchild(child2)) break;
                }
                TreeNode beta1 = nearestParent.getChild(beta1Index);
                TreeNode beta2 = nearestParent.getChild(beta2Index);
                if (!Collections.disjoint(beta1.getFollowLast(), beta2.getFirst())) {

                }
            }
        }
        return null;
    }

    private static int getCounting(String regex1, String regex2, String firstCharacter) throws InterruptedException {
//        String regex = reWriteMetaEscape("(" + regex1 + regex2 + ")");
//        if (isSpecialStringNeedAddSquareBracketsForDkBricsAutomaton(firstCharacter)) firstCharacter = "[" + firstCharacter + "]";
//        regex = "(" + regex + ")＆(" + firstCharacter + ".*)";
//        regex = reductSpecailStringForDkBricsAutomaton(regex);
////        System.out.println(regex);
//        RegExp regExp = new RegExp(regex);
//        Automaton automaton = regExp.toAutomaton(false);
////        System.out.println(automaton.getCommonPrefix());
////        System.out.println(automaton.getShortestExample(true).length());
//        String str = automaton.getShortestExample(true);
//        return (str == null) ? 0 : str.length();


        // .*要转义的
        List<String> regexList1 = new ArrayList<>();
        regexList1.add(regex1 + regex2);

        // .*不转义的
        List<String> regexList2 = new ArrayList<>();
        regexList2.add(firstCharacter + ".*");
        String str = getExampleByDkBricsAutomaton(regexList1, regexList2, 0);
        return (str == null) ? 0 : str.length();
    }

    // 生成中缀串forEOA
//    private static String generateInfixStringForEOA(String r0, String r1, String r2, String r3, String r4, String r5, int model, int counting) throws InterruptedException {
//        String regex = "1&2";
//        if (model == 1) {
//            String infix1 = getExampleByDkBricsAutomaton(new ArrayList<>(Collections.singleton(r0)), null, 0);
//            if (infix1 == null) return null;
//
//            String infix2 = getExampleByDkBricsAutomaton(new ArrayList<>(Arrays.asList(r1, r2 + r3)), null, counting);
//            if (infix2 == null) return null;
//
//            String infix3 = getExampleByDkBricsAutomaton(new ArrayList<>(Collections.singleton(regex4)), null, 0);
//            if (infix3 == null) return null;
//
//            return infix1 + infix2 + infix3;
//
//
////            regex0 = reWriteMetaEscape(regex0);
////            RegExp regExp = new RegExp(regex0);
////            Automaton automaton = regExp.toAutomaton(false);
////            String infix1 = automaton.getShortestExample(true);
////
////            if (infix1 == null) return null;
////
////            regex = reWriteMetaEscape("(" + regex1 + ")＆(" + regex3 + ")") + "＆(.{" + counting + "})";
////            regex = reductSpecailStringForDkBricsAutomaton(regex);
////            regExp = new RegExp(regex);
////            automaton = regExp.toAutomaton(false);    // 这里要加第二个参数minimize: false 这样就是nfa了 比dfa快
////            String infix2 = automaton.getShortestExample(true);
////
////            if (infix2 == null) return null;
////
////            regex4 = reWriteMetaEscape(regex4);
////            regExp = new RegExp(regex4);
////            automaton = regExp.toAutomaton(false);
////            String infix3 = automaton.getShortestExample(true);
////
////            if (infix3 == null) return null;
////
////            return infix1 + infix2 + infix3;
//        } else if (model == 2) {
//            String infix2 = getExampleByDkBricsAutomaton(new ArrayList<>(Collections.singleton(regex2)));
//            if (infix2 == null) return null;
//
//            String infix1 = getExampleByDkBricsAutomaton(new ArrayList<>(Arrays.asList(regex1, regex3)), null, counting);
//            if (infix1 == null) return null;
//
//            return infix1 + infix2;
//
////            regex2 = reWriteMetaEscape(regex2);
////            RegExp regExp = new RegExp(regex2);
////            Automaton automaton = regExp.toAutomaton(false);
////            String infix2 = automaton.getShortestExample(true);
////
////            if (infix2 == null) return null;
//
////            regex = reWriteMetaEscape("(" + regex1 + ")＆(" + regex3 + ")") + "＆(.{" + counting + "})";
////            regex = reductSpecailStringForDkBricsAutomaton(regex);
////            regExp = new RegExp(regex);
////            automaton = regExp.toAutomaton(false);
////            String infix1 = automaton.getShortestExample(true);
////
////            if (infix1 == null) return null;
////
////            return infix1 + infix2;
//        }
//        return null;
//    }


    private static ReDoSBean getEOARedosBeanHelper3(TreeNode root, String regex) throws InterruptedException {
        ReDoSBean bean = new ReDoSBean();
        ArrayList<AttackBean> attackBeanList = new ArrayList<>();
        Stack<TreeNode> stack = new Stack<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            TreeNode node = stack.pop();
            node = getGroupSubNode(node);
            if (isGeneralizedCountingNodeWithMaxNumGreaterThanOne(node)) {  // 外层要是个大counting
                String nodeCounting = node.getChild(1).getData();
                // 这里做个优化 {2,256} 这种直接改写为{2,}
                if (nodeCounting.contains(",")) {
                    nodeCounting = "{" + getCountingFirstNum(nodeCounting) + ",}";
                }

                // 条件1和条件2要击穿
                // 思路是找到当前结点的所有counting结点 生成r0 r1 r2 r3 r4 其中r1和r3是counting结点
                // 然后两两组合r1和r3 看是最近公共父节点是否为连接结点 若是 则为EOA
                List<TreeNode> allCountingChildren = node.getAllGeneralizedCountingWithMaxNumLeqOneNode();
                // 按索引从大到小排列
                allCountingChildren.sort(new Comparator<TreeNode>() {
                    @Override
                    public int compare(TreeNode treeNode1, TreeNode treeNode2) {
                        if (treeNode1.getChainIndex().compareTo(treeNode2.getChainIndex()) == 0) {
                            return 0;
                        }
                        String[] l1 = treeNode1.getChainIndex().split("\\.");
                        String[] l2 = treeNode2.getChainIndex().split("\\.");
                        int len = Math.min(l1.length, l2.length);
                        for (int i = 0; i < len; i++) {
                            int n1 = Integer.parseInt(l1[i]);
                            int n2 = Integer.parseInt(l2[i]);
                            if (n1 > n2) {
                                return -1;
                            } else if (n1 < n2) {
                                return 1;
                            }
                        }
                        return Integer.compare(l2.length, l1.length);
                    }
                });
                // 改为从小到大排
                Collections.reverse(allCountingChildren);

                for (int i = 0; i < allCountingChildren.size() - 1; i++) {
                    for (int j = i + 1; j < allCountingChildren.size(); j++) {
                        TreeNode child1 = allCountingChildren.get(i);
                        TreeNode child2 = allCountingChildren.get(j);
                        if (child1.isNowNodeChildOrGrandchild(child2) || child2.isNowNodeChildOrGrandchild(child1)) continue;
                        // 获取最近的爹
                        TreeNode nearestParent = getNearestParent(child1, child2);
                        // 最近的爹如果不是连接结点 则不是EOA
                        if (! (!isOrNode(nearestParent) && !isBracketsNode(nearestParent) && !nearestParent.isLeaf() && !isGeneralizedCountingNode(nearestParent) && nearestParent.getChildCount() >= 2) ) {    // 不是是连接结点
                            continue;
                        }
                        String r0 = getR0(node, child1);
                        String r1 = child1.getData();
                        String r2 = getR2(node, child1, child2);
                        String r3 = child2.getData();
                        String r4 = getR4(node, child2);




                        //beta1.followLast ∩ beta2.first ≠ ∅, 这里beta1 = r0r1, beta2 = r2r3r4
                        String beta1 = r0 + r1;
                        String beta2 = r2 + r3 + r4;
                        TreeNode beta1Tree = createReDoSTree(beta1);
                        TreeNode beta2Tree = createReDoSTree(beta2);
                        Set<String> beta1FollowLastSet = beta1Tree.getFollowLast();
                        Set<String> beta2FirstSet = beta2Tree.getFirst();
                        Set<String> intersection = new HashSet<>();    // 交集
                        intersection.addAll(beta1FollowLastSet);
                        intersection.retainAll(beta2FirstSet);
                        if (intersection.size() > 0) {
                            String firstCharacter = intersection.iterator().next();  // 获取第一个元素

                            int counting = getCounting(r1, r2 + r3, firstCharacter) + 1;
//                            System.out.println(counting);


                            // 反着找是是谁产生的followLast和first
                            String regex0 = ""; // 产生followLast的前面的子正则
                            String regex1 = ""; // 产生followLast的子正则
                            String regex2 = ""; // 产生first的子正则
                            String regex3 = ""; // 产生first的后面的子正则

//                            int counting = getCounting(regex1, regex2, firstCharacter) + 1;
////                            System.out.println(counting);
//
////                            int counting = getCountingFirstNum(regex1) + getCountingFirstNum(regex2) + 1;
////                            System.out.println("counting = " + counting);
//
//                            String infix = generateInfixStringForEOA(regex0, regex1, null, regex2, regex3, 1, counting);
//                            if (infix != null) {
//                                AttackBean attackBean = new AttackBean();
//                                attackBean.setPrefix(root.getMatchStr(node));
//                                attackBean.setRepeat(infix);
//                                attackBean.setSuffix(root.getNonMatchStr() + "_EOA(i)");
//                                attackBean.initType(AttackType.EXPONENT);
//                                attackBean.setPatternType(PatternType.EOA);
////                                    attackBean.setConflictPoint(new Pair<>());
//                                attackBeanList.add(attackBean);
//                            }
                        }
                    }
                }


            }

        }
        return null;
    }

    private static ReDoSBean getEOARedosBeanHelper(TreeNode root, String regex) throws InterruptedException {
        ReDoSBean bean = new ReDoSBean();
        ArrayList<AttackBean> attackBeanList = new ArrayList<>();
        Stack<TreeNode> stack = new Stack<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            TreeNode node = stack.pop();
            node = getGroupSubNode(node);
            TreeNode specialParent = getTheNearestParentWithMaxNumGreaterThanOneGeneralizedCounting(node);

            if (specialParent != null) {    // 外侧一定要有一个counting >1的爹
                String nodeCounting = specialParent.getChild(1).getData();
                // 这里做个优化 {2,256} 这种直接改写为{2,}
                if (nodeCounting.contains(",")) {
                    nodeCounting = "{" + getCountingFirstNum(nodeCounting) + ",}";
                }








                if (!isOrNode(node) && !isBracketsNode(node) && !node.isLeaf() && !isGeneralizedCountingNode(node) && node.getChildCount() >= 2) {    // 是连接结点
                    List<TreeNode> childList = node.getChildList();
                    // 分割
                    for (int i = 0; i < childList.size() - 1; i++) {
                        // nullable
                        // 若为连接结点 则对其所有的孩子结点 跳过无效值 求并集 若并集中含有false 则为false 否则为true

                        // first
                        // 若为连接结点 对其所有的孩子结点 从左到右找到第一个nullable为false的孩子 则包括该孩子在内的 前面所有的孩子的first求并集
                        //                                若找不到 则把所有的孩子的first集求并集

                        // followLast
                        // 若为连接结点 否则从右往左找到第一个nullable为false的结点 若存在 记为child(i) 最后一个孩子结点记为child(n)
                        //            该结点的followLast为 getChild(i).getFollowLast() ∪ ... ∪ getChild(n).getFollowLast() ∪ getChild(i+1).getFirst() ∪ ... ∪ getChild(n).getFirst()
                        //                               若不存在 则上式中i = 0 依然成立

                        StringBuilder beta1 = new StringBuilder();
                        StringBuilder beta2 = new StringBuilder();
                        int beta1Nullable = 1;
                        int beta2Nullable = 1;
//                    Set<String> beta1FirstSet = new HashSet<>();
                        Set<String> beta2FirstSet = new HashSet<>();
                        boolean beta1FirstNullableIsFalse = true;
                        boolean beta2FirstNullableIsFalse = true;
                        Set<String> beta1FollowLastSet = new HashSet<>();
//                    Set<String> beta2FollowLastSet = new HashSet<>();

                        for (int j = 0; j < childList.size(); j++) {
                            if (j <= i) {
                                beta1.append(childList.get(j).getData());
//                            // nullable
//                            if (beta1Nullable == 1 && beta1Nullable != -1) beta1Nullable = childList.get(j).getNullable();
//                            if (beta1FirstNullableIsFalse && beta1Nullable == 1) {
//                                beta1FirstSet.addAll(childList.get(j).getFirst());
//                            } else if (beta1FirstNullableIsFalse && beta1Nullable == 0) {
//                                beta1FirstSet.addAll(childList.get(j).getFirst());
//                                beta1FirstNullableIsFalse = false;
//                            }

                            } else {
                                beta2.append(childList.get(j).getData());
                                // nullable
                                if (beta2Nullable == 1 && beta2Nullable != -1)
                                    beta2Nullable = childList.get(j).getNullable();
                                if (beta2FirstNullableIsFalse && beta2Nullable == 1) {
                                    beta2FirstSet.addAll(childList.get(j).getFirst());
                                } else if (beta2FirstNullableIsFalse && beta2Nullable == 0) {
                                    beta2FirstSet.addAll(childList.get(j).getFirst());
                                    beta2FirstNullableIsFalse = false;
                                }
                            }
                        }

                        int j = i;
                        for (; j >= 0; j--) {
                            if (node.getChild(j).getNullable() == 0) break;
                        }
                        if (j == -1) j = 0; // 修复索引超限
                        beta1FollowLastSet.addAll(node.getChild(j).getFollowLast());
                        j += 1;
                        for (; j <= i; j++) {
                            beta1FollowLastSet.addAll(node.getChild(j).getFollowLast());
                            beta1FollowLastSet.addAll(node.getChild(j).getFirst());
                        }

//                    j = node.getChildCount() - 1;
//                    for (;  j > i ; j--) {
//                        if (node.getChild(j).getNullable() == 0) break;
//                    }
//                    if (j == -1) j = 0; // 修复索引超限
//                    beta2FollowLastSet.addAll(node.getChild(j).getFollowLast());
//                    j += 1;
//                    for (; j < node.getChildCount(); j++) {
//                        beta2FollowLastSet.addAll(node.getChild(j).getFollowLast());
//                        beta2FollowLastSet.addAll(node.getChild(j).getFirst());
//                    }

                        if (!Collections.disjoint(beta1FollowLastSet, beta2FirstSet)) {
                            Set<String> intersection = new HashSet<>();    // 交集
                            intersection.addAll(beta1FollowLastSet);
                            intersection.retainAll(beta2FirstSet);

                            // 反着找是是谁产生的followLast和first 这个first正则末尾node是要包含大于某个数的counting的
//                        String regex0 = ""; // 产生followLast的前面的子正则
                            String regex1 = ""; // 产生followLast的子正则
                            TreeNode regex1TreeNode = null; // 产生followLast的子正则
                            String regex2 = ""; // 产生first的子正则
//                        String regex3 = ""; // 产生first的后面的子正则

                            Set<String> regex1FollowLast = new HashSet<>(); // 动态记录产生followLast的子正则的followLast
                            int k1 = i, k2 = i + 1;
                            for (; k1 >= 0; k1--) {
                                if (!regex1FollowLast.containsAll(intersection)) {
                                    regex1FollowLast.addAll(childList.get(k1).getFollowLast());
                                    regex1 = childList.get(k1).getData() + regex1;
                                    regex1TreeNode = childList.get(k1);
                                } else {
                                    break;
                                }
                            }

//                        for (; k1 >= 0; k1--) {
//                            regex0 = childList.get(k1).getData() + regex0;
//                        }

                            // 获取所有的counting孩子结点
                            List<TreeNode> allCountingChildren = node.getAllGeneralizedCountingWithMaxNumLeqOneNode();
                            // 刨除含有regex1TreeNode结点
                            for (int k = allCountingChildren.size() - 1; k >= 0; k--) {
                                if (regex1TreeNode.isNowNodeChildOrGrandchild(allCountingChildren.get(k)) || regex1TreeNode == allCountingChildren.get(k)) {
                                    allCountingChildren.remove(k);
                                }
                            }
//                        allCountingChildren.remove(regex1TreeNode);
//                        System.out.println(regex1TreeNode.getData());
//                        System.out.println(allCountingChildren);
//                        System.out.println("regex1 = " + regex1);

                            // 如果node的爹们的counting都小于1 铁定是POA
                            if (isAllParentCountingLessOrEqualToOne(node)) {
                                for (int k = 0; k < allCountingChildren.size(); k++) {
                                    String r2 = getR2(node, regex1TreeNode, allCountingChildren.get(k));

                                    String infix = generateInfixStringForPOA(regex1, r2, allCountingChildren.get(k).getData());
//                                System.out.println(regex1 + " " + r2 + " " + allCountingChildren.get(k).getData() + " " + infix);
                                    if (infix != null) {
                                        AttackBean attackBean = new AttackBean();
                                        attackBean.setPrefix(root.getMatchStr(regex1TreeNode));
                                        attackBean.setInfix(infix);
                                        attackBean.setSuffix(root.getNonMatchStr() + "_POA(i)");
                                        attackBean.initType(AttackType.POLYNOMIAL);
//                                        attackBean.setPatternType(PatternType.POA);
//                                    attackBean.setConflictPoint(new Pair<>());
                                        attackBeanList.add(attackBean);
                                    }
                                }
                            } else {    // 否则就可能是EOA了 (a*aa*c)*就是POA    (a*aa*c?)*就是EOA
                                for (int k = 0; k < allCountingChildren.size(); k++) {
//                                    String r4 = getR4(node, regex1TreeNode, allCountingChildren.get(k));
                                    String r4 = getR4(node, allCountingChildren.get(k));
                                    if (isPOAnotEOA(regex1, allCountingChildren.get(k).getData(), r4)) {
                                        String r2 = getR2(node, regex1TreeNode, allCountingChildren.get(k));
                                        String infix = generateInfixStringForPOA(regex1, r2, allCountingChildren.get(k).getData());
//                                    System.out.println(infix);
                                        if (infix != null) {
                                            AttackBean attackBean = new AttackBean();
                                            attackBean.setPrefix(root.getMatchStr(regex1TreeNode));
                                            attackBean.setInfix(infix);
                                            attackBean.setSuffix(root.getNonMatchStr() + "_POA(ii)");
                                            attackBean.initType(AttackType.POLYNOMIAL);
//                                            attackBean.setPatternType(PatternType.POA);
//                                    attackBean.setConflictPoint(new Pair<>());
                                            attackBeanList.add(attackBean);
                                        }
                                    }
                                }
                            }
                        }
                    }

                }
            }



            for (int i = node.getChildCount() - 1; i >= 0; i--) {
                stack.push(node.getChild(i));
            }
        }
        if (attackBeanList.size() > 0) {
            bean.setAttackBeanList(attackBeanList);
            bean.setReDoS(true);
        } else {
            bean.setReDoS(false);
        }
        return bean;
    }

    public static ReDoSBean getEOARedosBean(String regex) {
        ReDoSBean bean = new ReDoSBean();
        try {
            TreeNode tree = getRedosTree(regex);
            bean = getEOARedosBeanHelper(tree, regex);
        } catch (InterruptedException e) {
            bean.setReDoS(false);
        } catch (Exception e) {
            System.out.println(regex);
            e.printStackTrace();
            bean.setMessage("PARSE ERROR");
            bean.setReDoS(false);
        }
        return bean;
    }

    public static void main(String[] args) throws InterruptedException {
        String regex = "a*a[a-c](c|a*b)a";
        regex = "(a*(b|c)(a(a*)d))*e";
        regex = "a*(b|(ca*))?";
        regex = "(a*b)+(c|ea*)f";
        regex = "((a*b)+(c|ea*)f)*";
        regex = "a*a*";
        regex = "((((ab|xy)c)d)e)+";
        regex = "ab|xy";
        TreeNode tree = createReDoSTree(regex);
        printTree(tree);
//        TreeNode left = tree.getChild(0);
//        TreeNode right = tree.getChild(3).getChild(1).getChild(2).getChild(0);
//        TreeNode left = tree.getChild(0).getChild(0).getChild(1).getChild(0);
//        TreeNode right = tree.getChild(0).getChild(0).getChild(1).getChild(2).getChild(1).getChild(1).getChild(1);
//        TreeNode left = tree.getChild(0);
//        TreeNode right = tree.getChild(1).getChild(0).getChild(1).getChild(2).getChild(1).getChild(1);
//        TreeNode left = tree.getChild(0).getChild(0).getChild(1).getChild(0);
//        TreeNode right = tree.getChild(1).getChild(1).getChild(2).getChild(1);
//        TreeNode left = tree.getChild(0).getChild(1).getChild(0).getChild(0).getChild(1).getChild(0);
//        TreeNode right = tree.getChild(0).getChild(1).getChild(1).getChild(1).getChild(2).getChild(1);
//        TreeNode left = tree.getChild(0);
//        TreeNode right = tree.getChild(1);
//        TreeNode left = tree.getChild(0).getChild(1).getChild(0).getChild(1).getChild(0).getChild(1).getChild(0).getChild(1).getChild(0).getChild(0);
//        TreeNode right = tree.getChild(0).getChild(1).getChild(0).getChild(1).getChild(0).getChild(1).getChild(0).getChild(1).getChild(0).getChild(1);
        TreeNode left = tree.getChild(2).getChild(0);
        TreeNode right = tree.getChild(2).getChild(1);
        System.out.println(left.getData());
        System.out.println(right.getData());
        System.out.println("---");
        System.out.println(getR0(tree, left));
        System.out.println(getR0(tree, right));
        System.out.println("---");
        System.exit(0);




        String regex1 = "@@@[1abc]+1abc\\w+2222\\w+!!!";
        regex = "a(\\w+|abc)d\\w+";
        regex = "(?P<amount>-?\\d+(?:\\.\\d*)?)[^\\S\\n]*(?P<degrees>°|deg(?:rees?)?|in)?[^\\S\\n]*(?P<unit>c(?:(?=el[cs]ius\\b|entigrades?\\b|\\b))|f(?:(?=ahrenheit\\b|\\b))|k(?:(?=elvins?\\b|\\b)))";
        regex = ".*(0a)?.*";
        regex = "<table.*?>(([\\s*].*(\\s*))+)?<\\/table>";
        regex = "(?<a>.*)(?<b>[0-9]\\.([0-9]*c)d$)";
        regex = "(ba*a(d|aa*)c)*";
        regex = "^(\\s*([,;]|$)+\\s*)*$";
//        regex = ".*c((a.*(b))+)?";
        TreeNode newlyttree = getRedosTree(regex);
        printTree(newlyttree);
//        TreeNode right = newlyttree.getChild(0).getChild(1).getChild(3).getChild(1).getChild(2).getChild(1);
//        System.out.println(right.getData());
//        System.out.println(getR4(newlyttree, right));
//        TreeNode left = newlyttree.getChild(0);
//        TreeNode right = newlyttree.getChild(2).getChild(0).getChild(1).getChild(0).getChild(1).getChild(1);
//        System.out.println(left.getData() + " " + right.getData());
//        System.out.println(getR2(newlyttree, left, right));
//        System.exit(0);
//        System.out.println(isAllParentCountingLessOrEqualToOne(newlyttree.getChild(0).getChild(1).getChild(0).getChild(1).getChild(0)));
//        System.out.println(getOrSymbolTreeNode(newlyttree.getChild(0)));
        ReDoSBean reDosBean = getEOARedosBean(regex);
        ArrayList<AttackBean> attackBeanList = reDosBean.getAttackBeanList();
        for (int i = 0; i < attackBeanList.size(); i++) {
            System.out.println(attackBeanList.get(i).getAttackStringFormat());
        }
    }

}
