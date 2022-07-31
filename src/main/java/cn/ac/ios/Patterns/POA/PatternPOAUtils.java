package cn.ac.ios.Patterns.POA;

import cn.ac.ios.TreeNode.TreeNode;
import cn.ac.ios.Bean.*;
import cn.ac.ios.Utils.Constant;

import java.util.*;

import static cn.ac.ios.TreeNode.Utils.*;
import static cn.ac.ios.Utils.BracketUtils.simplifyLetters;
import static cn.ac.ios.Utils.Constant.*;
import static cn.ac.ios.Utils.FlagsUtils.*;
import static cn.ac.ios.Utils.NegateUtils.*;
import static cn.ac.ios.Utils.RegexUtils.*;
import static cn.ac.ios.Utils.Utils.getIntersection;

/**
 * @author pqc
 */
public class PatternPOAUtils {

    public static final String NO_LETTER_MATCH = "IOS_AC_CN_NO_LETTER_MATCH";


    /**
     * 获取不匹配后缀
     *
     * @param regex
     * @return
     * @throws InterruptedException
     * @Deprecated
     */
    public static String getSuffix(String regex) {
        try {
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

            newlyttree = refactorAssertPattern(newlyttree);

            // 处理\x{....} \xff
            newlyttree.escapeHexadecimal();
            // 删除Flags
            newlyttree = getNodeByRemoveRegExpFlag(newlyttree);


            newlyttree = getNodeByRemoveLocalFlag(newlyttree);

            // 使用重写后的去首尾^$
            newlyttree.deleteCaretAndDollarSymbols();

            // 获取后缀

            return getSuffixByNegateNode(newlyttree);
        } catch (Exception e) {
            return "!@ \n_1";
        }
    }

    /**
     * 预处理
     *
     * @param regex
     * @return
     * @throws InterruptedException
     */
    private static TreeNode getReDoSTree(String regex) throws InterruptedException {
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
        // 去group name
        regex = deleteGroupName(regex);

        // 建树
        TreeNode newlyttree = createReDoSTree(regex);

        newlyttree = refactorAssertPattern(newlyttree);

        // 处理\x{....} \xff
        newlyttree.escapeHexadecimal();
        // 删除Flags
        newlyttree = getNodeByRemoveRegExpFlag(newlyttree);

        newlyttree = getNodeByRemoveLocalFlag(newlyttree);

        // 使用重写后的去首尾^$
        newlyttree.deleteCaretAndDollarSymbols();

        regex = rewriteEmptyString(newlyttree.getData());

        if (!regex.equals(newlyttree.getData())) {
            newlyttree = createReDoSTree(regex);
        }
        // 重写反向引用
        newlyttree.rewriteBackreferences();
        // 去补
        removeNegateSymbol(newlyttree, SimplyLevel.HIGH);

        newlyttree = removeGroup(newlyttree);

        newlyttree = removeGroup(newlyttree);

        return newlyttree;
    }


    public static ReDoSBean getPOAReDoSBean(String regex) {
        ReDoSBean bean = new ReDoSBean();
        try {
            TreeNode root = getReDoSTree(regex);
            bean = getPOAReDoSBeanHelper(root, regex);
        } catch (InterruptedException e) {
            bean.setReDoS(false);
        } catch (Exception e) {
            bean.setMessage("PARSE ERROR");
            bean.setReDoS(false);
        }
        return bean;
    }


    /**
     * POA模式 获取攻击串
     * 多项式 ，支持嵌套
     *
     * @return
     */
    @Deprecated
    public static ReDoSBean getPOAReDoSBeanHelper(TreeNode ReDoSTree, String regex, int count) {
        if (isGroupNode(ReDoSTree)) {
            return getPOAReDoSBeanHelper(ReDoSTree.getChild(1), ReDoSTree.getChild(1).getData(), count);
        }
        ReDoSBean bean = new ReDoSBean();
        if (ReDoSTree.getData().length() < 4) {
            return bean;
        }
        int temp = count;
        List<TreeNode> treeNodeList = ReDoSTree.getChildList();
        ArrayList<Integer> dotList = new ArrayList<>();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < treeNodeList.size(); i++) {
            if (treeNodeList.get(i).isReferencesNode()) {
                stringBuilder.append(treeNodeList.get(i).getMatchStr());
                continue;
            }
            if (isSetRepeatNode(treeNodeList.get(i)) || isSingleCountingNode(treeNodeList.get(i))) {
                dotList.add(i);
            }
            if (isGeneralizedCountingNode(treeNodeList.get(i))) {
                count++;
            }
            if (treeNodeList.get(i).getData().length() >= 4) {
                ReDoSBean subBean = getPOAReDoSBeanHelper(treeNodeList.get(i), treeNodeList.get(i).getData(), count);
                if (subBean.isReDoS()) {
                    for (AttackBean attackBean : subBean.getAttackBeanList()) {
                        attackBean.setPrefix(stringBuilder.toString() + attackBean.getPrefix());
                    }
                    bean.getAttackBeanList().addAll(subBean.getAttackBeanList());
                }
            }
            stringBuilder.append(treeNodeList.get(i).getMatchStr());
        }
        if (dotList.size() >= 2) {
            for (int i = 0; i < dotList.size() - 1; i++) {
                for (int j = i + 1; j < dotList.size(); j++) {
                    AttackBean attack;
                    try {
                        attack = getAttackBean(treeNodeList, dotList.get(i), dotList.get(j));
                    } catch (InterruptedException e) {
                        return bean;
                    }
                    if (attack != null) {
//                        attack.setPatternType(PatternType.POA);
//                        attack.setConflictPoint(new Pair<>(temp + i + 1, temp + j + 1));
                        bean.setReDoS(true);
                        bean.getAttackBeanList().add(attack);
                    }
                }
            }
        }
        if (!bean.getAttackBeanList().isEmpty()) {
            bean.setReDoS(true);
        }
        return bean;
    }

    /**
     * POA模式 获取攻击串
     * 多项式 ，支持嵌套
     *
     * @return
     */
    public static ReDoSBean getPOAReDoSBeanHelper(TreeNode ReDoSTree, String regex) {
        if (isGroupNode(ReDoSTree)) {
            return getPOAReDoSBeanHelper(ReDoSTree.getChild(1), ReDoSTree.getChild(1).getData());
        }
        ReDoSBean bean = new ReDoSBean();
        if (ReDoSTree.getData().length() < 4) {
            return bean;
        }
        ArrayList<TreeNode> dotList = new ArrayList<>();
        Stack<TreeNode> stack = new Stack<>();
        stack.push(ReDoSTree);
        while (!stack.isEmpty()) {
            TreeNode node = stack.pop();
            if (node.isReferencesNode()) {
                continue;
            }
            if (isGeneralizedCountingNode(node)) {
                dotList.add(getGroupSubNode(node));
            } else {
                for (int i = node.getChildCount() - 1; i >= 0; i--) {
                    stack.push(node.getChild(i));
                }
            }
        }
        if (dotList.size() >= 2) {
            for (int i = 0; i < dotList.size() - 1; i++) {
                for (int j = i + 1; j < dotList.size(); j++) {
                    TreeNode left = dotList.get(i);
                    TreeNode right = dotList.get(j);
//                    try {
//                        AttackBean attack = getAttackBean(newlyttree, left, right);
//                        if (attack != null) {
//                            attack.setPatternType(PatternType.POA);
//                            attack.setConflictPoint(new Pair<>(i, j));
//                            bean.getAttackBeanList().add(attack);
//                        }
//                    } catch (InterruptedException e) {
//                        return bean;
//                    }
                }
            }
        }
        if (!bean.getAttackBeanList().isEmpty()) {
            bean.setReDoS(true);
        }
        return bean;
    }

    /**
     * 从两个集合节点生成攻击串，支持嵌套和不同层次
     *
     * @param root
     * @param left
     * @param right
     * @return
     */
    // 截取两个counting结点之间的正则 不包含两端 输入中left = left2 都是左counting结点 right = right2 都是右counting结点
    @Deprecated
    private static String getR2(TreeNode root, TreeNode left, TreeNode right) {
        TreeNode left2 = left;      // left的备份指针
        TreeNode right2 = right;    // right的备份指针

        String leftRegex = left.getData();
        StringBuilder midRegex = new StringBuilder();
        StringBuilder rightRegex = new StringBuilder(right.getData());
        boolean start = false;
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
    }

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


    public static void main(String[] args) throws InterruptedException {
        String regex = "a*a[a-c](c|a*b)a";
//        regex = "(a*(b|c)(a(a*)d))*e";
//        regex = "a*(b|(ca*))?";
//        regex = "(a*b)+(c|ea*)f";
//        regex = "((a*b)+(c|ea*)f)*";
//        regex = "a*a*";
        TreeNode tree = createReDoSTree(regex);
        printTree(tree);
        TreeNode left = tree.getChild(0);
        TreeNode right = tree.getChild(3).getChild(1).getChild(2).getChild(0);
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
//        System.out.println(left.getData());
//        System.out.println(right.getData());
        System.out.println(getR2(tree, left, right));
        System.out.println(getR4(tree, left, right));
    }

    /**
     * 获取指数级的redos
     * waring：只能解决部分问题，并不全面，可作为补充。
     *
     * @param newlyttree
     * @return
     */
    @Deprecated
    private static ReDoSBean getExponentRedos(TreeNode newlyttree) {
        ReDoSBean bean = new ReDoSBean();
        List<TreeNode> treeNodeList = newlyttree.getChildList();
        ArrayList<Integer> exponentNodes = new ArrayList<>();
        for (int i = 0; i < treeNodeList.size(); i++) {
            if (isExponentNode(treeNodeList.get(i))) {
                exponentNodes.add(i);
            }
        }
        if (isExponentNode(newlyttree)) {
            ArrayList<AttackBean> attackBeans;
            ArrayList<TreeNode> list = new ArrayList<>();
            list.add(newlyttree);
            try {
                attackBeans = getAttackBean(list, 0);
            } catch (InterruptedException e) {
                return bean;
            }
            if (!attackBeans.isEmpty()) {
                bean.setReDoS(true);
                bean.getAttackBeanList().addAll(attackBeans);
            }
        }

        for (int i = 0; i < exponentNodes.size(); i++) {
            ArrayList<AttackBean> attackBeans;
            try {
                attackBeans = getAttackBean(treeNodeList, exponentNodes.get(i));
            } catch (InterruptedException e) {
                return bean;
            }
            if (!attackBeans.isEmpty()) {
                bean.setReDoS(true);
                bean.getAttackBeanList().addAll(attackBeans);
            }
        }
        return bean;
    }

    /**
     * 获取指数级redos的攻击串
     *
     * @param treeNodeList
     * @param index
     * @return
     * @throws InterruptedException
     */
    @Deprecated
    private static ArrayList<AttackBean> getAttackBean(List<TreeNode> treeNodeList, int index) throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException();
        }
        ArrayList<AttackBean> attackBeans = new ArrayList<>();
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < index; i++) {
            String data = treeNodeList.get(i).getMatchStr();
            prefix.append(data);
        }
        String suffix = "";
        for (int i = index + 1; i < treeNodeList.size(); i++) {
            String data = treeNodeList.get(i).getNonMatchStr();
            if (data.length() > 0) {
                suffix = data;
                break;
            }
        }
        if ("".equals(suffix)) {
            suffix = "!@◎\n_POA_E";
        }
        TreeNode node = treeNodeList.get(index).getChild(0).getChild(1);
        if (isOrNode(node)) {
            node = getGroupSubNode(node);
            for (int i = 0; i < node.getChildCount(); i++) {
                TreeNode child = node.getChild(i);
                if (!"|".equals(child.getData())) {
                    ArrayList<String> repeat = getExponentAttackStr(child);
                    for (String str : repeat) {
                        AttackBean bean = new AttackBean();
                        bean.initType(AttackType.EXPONENT);
                        bean.setPrefix(prefix.toString());
                        bean.setInfix(str);
                        bean.setSuffix(suffix + "_POA_E");
                        attackBeans.add(bean);
                    }
                }
            }

        } else {
            ArrayList<String> repeat = getExponentAttackStr(node);
            for (String str : repeat) {
                AttackBean bean = new AttackBean();
                bean.initType(AttackType.EXPONENT);
                bean.setPrefix(prefix.toString());
                bean.setInfix(str);
                bean.setSuffix(suffix + "_POA_E");
                attackBeans.add(bean);
            }
        }
        return attackBeans;
    }

    /**
     * 获取指数级攻击串
     *
     * @param child
     * @return waring：非必需
     */
    @Deprecated
    private static ArrayList<String> getExponentAttackStr(TreeNode child) {
        ArrayList<String> arrayList = new ArrayList<>();
        if (isStarNode(child)) {
            arrayList.add(child.getMatchStrWithCounting());
            return arrayList;
        }
        List<TreeNode> treeNodeList = child.getChildList();
        // 处理多项式
        ArrayList<Integer> dotList = new ArrayList<>();
        for (int i = 0; i < treeNodeList.size(); i++) {
            String data = treeNodeList.get(i).getData();
            if (data.equals(".*") || data.equals(".+")) {
                dotList.add(i);
            } else if (data.equals("(.*)") || data.equals("(.+)") || data.equals("(.)*") || data.equals("(.)+")) {
                dotList.add(i);
            } else if (isStarNode(treeNodeList.get(i))) {
                dotList.add(i);
            }
        }
        if (dotList.size() == 1) {
            StringBuilder stringBuilder = new StringBuilder();
            int id = dotList.get(0);
            for (int i = 0; i < id - 1; i++) {
                stringBuilder.append(treeNodeList.get(i).getMatchStrWithCounting());
            }
            if (id - 1 >= 0) {
                stringBuilder.append(treeNodeList.get(id - 1).getMatchStrWithCounting());
                stringBuilder.append(treeNodeList.get(id - 1).getMatchStrWithCounting());
            }
            for (int i = id + 1; i < treeNodeList.size(); i++) {
                stringBuilder.append(treeNodeList.get(i).getMatchStrWithCounting());
            }
            arrayList.add(stringBuilder.toString());

            stringBuilder = new StringBuilder("");
            for (int i = 0; i < id; i++) {
                stringBuilder.append(treeNodeList.get(i).getMatchStrWithCounting());
            }
            if (id + 1 < treeNodeList.size()) {
                stringBuilder.append(treeNodeList.get(id + 1).getMatchStrWithCounting());
                stringBuilder.append(treeNodeList.get(id + 1).getMatchStrWithCounting());
            }
            for (int i = id + 2; i < treeNodeList.size(); i++) {
                stringBuilder.append(treeNodeList.get(i).getMatchStrWithCounting());
            }
            arrayList.add(stringBuilder.toString());
        } else {
            for (int i = 0; i < dotList.size() - 1; i++) {
                for (int j = i + 1; j < dotList.size(); j++) {
                    int left = dotList.get(i);
                    int right = dotList.get(j);
                    StringBuilder stringBuilder = new StringBuilder();
                    for (int k = 0; k < left; k++) {
                        stringBuilder.append(treeNodeList.get(k).getMatchStrWithCounting());
                    }
                    if (left + 1 == right) {
                        stringBuilder.append(treeNodeList.get(left).getMatchStrWithCounting());
                        stringBuilder.append(treeNodeList.get(right).getMatchStrWithCounting());
                    } else {
                        StringBuilder s = new StringBuilder();
                        for (int k = left + 1; k < right; k++) {
                            s.append(treeNodeList.get(k).getMatchStrWithCounting());
                        }
                        stringBuilder.append(s).append(s).append(s);
                    }
                    for (int k = right + 1; k < treeNodeList.size(); k++) {
                        stringBuilder.append(treeNodeList.get(k).getMatchStrWithCounting());
                    }
                    arrayList.add(stringBuilder.toString());
                }
            }
        }
        Set<String> set = new HashSet<>(arrayList);
        return new ArrayList<>(set);
    }

    /**
     * 从指定两个集合节点生成攻击串
     * 多项式
     *
     * @param treeNodeList
     * @param left
     * @param right
     * @return
     */
    @Deprecated
    public static AttackBean getAttackBean(List<TreeNode> treeNodeList, int left, int right) throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException();
        }
        if (left + 1 == right) {
            return getAttackStringByConflict(left, right, treeNodeList);
        }
        return getAttackString(left, right, treeNodeList);
    }

    /**
     * 从相邻的两个集合节点生成攻击串，重复两个节点的公共字串
     *
     * @param left
     * @param right
     * @param treeNodeList
     * @return
     */
    private static AttackBean getAttackStringByConflict(int left, int right, List<TreeNode> treeNodeList) {
        AttackBean bean = new AttackBean();
        bean.initType(AttackType.POLYNOMIAL);
//        bean.setConflictPoint(new Pair<>(left, right));
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < left; i++) {
            String data = treeNodeList.get(i).getMatchStr();
            prefix.append(data);
        }
        bean.setPrefix(prefix.toString());
        StringBuilder attack = new StringBuilder();
        Set<String> leftSet = treeNodeList.get(left).getLetterSet(false);
        Set<String> rightSet = treeNodeList.get(right).getLetterSet(false);
        // 空表示节点为 .* 支持除空白符任意字符
        if (leftSet.isEmpty() && rightSet.isEmpty()) {
            attack.append("11");
        } else {
            List<String> list = new ArrayList<>(getIntersection(leftSet, rightSet));
            if (list.isEmpty()) {
                return null;
            }
            list.sort(Comparator.naturalOrder());
            String temp = list.get(0);
            for (String str : list) {
                if (str.length() == 1) {
                    char c = str.charAt(0);
                    if (Character.isLowerCase(c) || Character.isUpperCase(c) || Character.isDigit(c)) {
                        temp = String.valueOf(c);
                        break;
                    } else if (c >= 41) {
                        temp = String.valueOf(c);
                    }
                }
            }
            attack.append(temp);
        }
        bean.setInfix(attack.toString());
        String suffix = "";
        for (int i = right + 1; i < treeNodeList.size(); i++) {
            String data = treeNodeList.get(i).getNonMatchStr();
            if (data.length() > 0) {
                suffix = data;
                break;
            }
        }
        bean.setSuffix(suffix);
        if ("".equals(suffix)) {
            if (right == treeNodeList.size() - 1) {
                if (rightSet.isEmpty()) {
                    bean.setSuffix("◎\n_POA");
                } else {
                    bean.setSuffix(treeNodeList.get(right).getNonMatchStr() + "_POA");
                }
            } else {
                return null;
            }
        } else {
            bean.setSuffix(bean.getSuffix() + "_POA");
        }
        return bean;
    }

    /**
     * 获取攻击串
     *
     * @param left
     * @param right
     * @param treeNodeList
     * @return
     */
    private static AttackBean getAttackString(int left, int right, List<TreeNode> treeNodeList) {
        AttackBean bean = new AttackBean();
        bean.initType(AttackType.POLYNOMIAL);
//        bean.setConflictPoint(new Pair<>(left, right));
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < left; i++) {
            String data = treeNodeList.get(i).getMatchStr();
            prefix.append(data);
        }
        bean.setPrefix(prefix.toString());
        StringBuilder attack = new StringBuilder();
        Set<String> leftSet = treeNodeList.get(left).getLetterSet(false);
        Set<String> rightSet = treeNodeList.get(right).getLetterSet(false);
        // 空表示节点为 .* 支持除空白符任意字符
        if (leftSet.isEmpty() && rightSet.isEmpty()) {
            for (int i = left + 1; i < right; i++) {
                String data = treeNodeList.get(i).getMatchStr();
                attack.append(data);
            }
        } else {
            List<String> list = new ArrayList<>(getIntersection(leftSet, rightSet));
            if (list.isEmpty()) {
                return null;
            }
            list.sort(Comparator.naturalOrder());
            for (int i = left + 1; i < right; i++) {
                List<String> conflictSet = new ArrayList<>(list);
                String data = treeNodeList.get(i).getMatchStr(conflictSet);
                if (NO_LETTER_MATCH.equals(data)) {
                    return null;
                } else {
                    attack.append(data);
                }
            }
        }
        if (attack.length() == 0) {
            return getAttackStringByConflict(left, right, treeNodeList);
        }
        bean.setInfix(attack.toString());
        String suffix = "";
        for (int i = right + 1; i < treeNodeList.size(); i++) {
            String data = treeNodeList.get(i).getNonMatchStr();
            if (data.length() > 0) {
                suffix = data;
                break;
            }
        }
        bean.setSuffix(suffix);
        if ("".equals(suffix)) {
            if (right == treeNodeList.size() - 1) {
                if (rightSet.isEmpty()) {
                    bean.setSuffix("\n_POA");
                } else {
                    bean.setSuffix(treeNodeList.get(right).getNonMatchStr() + "_POA");
                }
            } else {
                return null;
            }
        } else {
            bean.setSuffix(bean.getSuffix() + "_POA");
        }
        return bean;
    }

    /**
     * 判断 dot redos
     *
     * @param treeNodeList
     * @return
     */
    @Deprecated
    public static ReDoSBean isDotRedos(List<TreeNode> treeNodeList) {

        ReDoSBean bean = new ReDoSBean();
        int left = -1;
        int right = -1;
        int count = 0;
        int i = 0;
        boolean flag = false;
        for (TreeNode child : treeNodeList) {
            String data = child.getData();
            if (data.equals(".*") || data.equals(".+") || data.equals("(.*)") || data.equals("(.+)") || data.equals("(.)*") || data.equals("(.)+")) {
                count++;
                if (count == 1) {
                    left = i;
                }
                if (count >= 2) {
                    right = i;
                    flag = true;
                }
            }
            i++;
        }
        if (right == treeNodeList.size() - 1) {
            bean.setReDoS(false);
            return bean;
        }

        // .不包括 \n
        for (int j = left + 1; j < right; j++) {
            if (treeNodeList.get(j).getLetterSetMustHas().contains("\\n")) {
                bean.setReDoS(false);
                return bean;
            }
        }

        // 结尾没有字符，无法回溯
        Set<String> set = new HashSet<>();
        for (int j = right + 1; j < treeNodeList.size(); j++) {
            set.addAll(treeNodeList.get(j).getLetterSetMustHas());
        }
        if (set.isEmpty()) {
            bean.setReDoS(false);
            return bean;
        }

        // 如果结尾  . 前后节点的的字符内容一样，无法回溯
        if (right == treeNodeList.size() - 2) {
            TreeNode before = treeNodeList.get(right - 1);
            TreeNode after = treeNodeList.get(right + 1);
            if (before.getData().equals(after.getData())) {
                bean.setReDoS(false);
                return bean;
            }
        }

        if (flag) {
            AttackBean attack = getDotAttackString(left, right, treeNodeList);
            ArrayList<AttackBean> list = new ArrayList<>();
            list.add(attack);
            bean.setAttackBeanList(list);
        }
        bean.setReDoS(flag);
        return bean;
    }

    /**
     * 获取 dot redos信息
     *
     * @return
     */
    @Deprecated
    public static ReDoSBean getDotRedosBean(TreeNode newlyttree, String regex) {
        List<TreeNode> treeNodeList = newlyttree.getChildList();
        ReDoSBean bean = new ReDoSBean();
        ArrayList<Integer> dotList = new ArrayList<>();
        for (int i = 0; i < treeNodeList.size(); i++) {
            String data = treeNodeList.get(i).getData();
            if (data.equals(".*") || data.equals(".+")) {
                dotList.add(i);
            } else if (data.equals("(.*)") || data.equals("(.+)") || data.equals("(.)*") || data.equals("(.)+")) {
                dotList.add(i);
            }
        }
        if (dotList.size() >= 2) {
            for (int i = 0; i < dotList.size() - 1; i++) {
                for (int j = i + 1; j < dotList.size(); j++) {
                    AttackBean attack = getDotAttackBean(treeNodeList, dotList.get(i), dotList.get(j));
                    if (attack != null) {
                        bean.setReDoS(true);
                        bean.getAttackBeanList().add(attack);
                    }
                }
            }
        }
        return bean;
    }

    @Deprecated
    public static AttackBean getDotAttackBean(List<TreeNode> treeNodeList, int left, int right) {
        AttackBean bean;
        if (right == treeNodeList.size() - 1) {
            return null;
        }

        // .不包括 \n
        for (int j = left + 1; j < right; j++) {
            if (treeNodeList.get(j).getLetterSetMustHas().contains("\\n")) {
                return null;
            }
        }

        // 结尾没有字符，无法回溯
        Set<String> set = new HashSet<>();
        for (int j = right + 1; j < treeNodeList.size(); j++) {
            set.addAll(treeNodeList.get(j).getLetterSetMustHas());
        }
        if (set.isEmpty()) {
            return null;
        }

        // 如果结尾  . 前后节点的的字符内容一样，无法回溯
        if (right == treeNodeList.size() - 2) {
            TreeNode before = treeNodeList.get(right - 1);
            TreeNode after = treeNodeList.get(right + 1);
            if (before.getData().equals(after.getData())) {
                return null;
            }
        }


        bean = getDotAttackString(left, right, treeNodeList);
        return bean;
    }

    /**
     * 获取攻击串
     *
     * @param left
     * @param right
     * @param treeNodeList
     * @return
     */
    @Deprecated
    public static AttackBean getDotAttackString(int left, int right, List<TreeNode> treeNodeList) {
        AttackBean bean = new AttackBean();
//        bean.setConflictPoint(new Pair<>(left, right));
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < left; i++) {
            String data = treeNodeList.get(i).getMatchStr();
            prefix.append(data);
        }
        bean.setPrefix(prefix.toString());
        StringBuilder attack = new StringBuilder();
        for (int i = left + 1; i < right; i++) {
            String data = treeNodeList.get(i).getMatchStr();
            attack.append(data);
        }
        bean.setInfix(attack.toString());
        String suffix = "";
        for (int i = right + 1; i < treeNodeList.size(); i++) {
            String data = treeNodeList.get(i).getNonMatchStr();
            if (data.length() > 0) {
                suffix = data;
                break;
            }
        }
        bean.setSuffix(suffix);
        if ("".equals(suffix)) {
            return null;
        } else {
            return bean;
        }
    }

    /**
     * 获取匹配串
     *
     * @param left
     * @param right
     * @param treeNodeList
     * @return
     */
    @Deprecated
    public static AttackBean getMatchString(int left, int right, List<TreeNode> treeNodeList) {
        AttackBean bean = new AttackBean();
//        bean.setConflictPoint(new Pair<>(left, right));
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < left; i++) {
            String data = treeNodeList.get(i).getMatchStr();
            prefix.append(data);
        }
        bean.setPrefix(prefix.toString());
        StringBuilder attack = new StringBuilder();
        for (int i = left + 1; i < right; i++) {
            String data = treeNodeList.get(i).getMatchStr();
            attack.append(data);
        }
        bean.setInfix(attack.toString());
        StringBuilder suffix = new StringBuilder();
        for (int i = right + 1; i < treeNodeList.size(); i++) {
            String data = treeNodeList.get(i).getNonMatchStr();
            suffix.append(data);
        }
        bean.setSuffix(suffix.toString());
        return bean;
    }


    @Deprecated
    public static boolean isNumberRedos(List<TreeNode> treeNodeList) {
        int left = -1;
        int right = -1;
        int count = 0;
        int i = 0;
        boolean flag = false;
        for (TreeNode child : treeNodeList) {
            String data = child.getData();
            if (data.equals("[\\d]+") || data.equals("[\\d]*") || data.equals("([\\d]*)") || data.equals("([\\d]+)") || data.equals("([\\d])*") || data.equals("([\\d])+")) {
                count++;
                if (count == 1) {
                    left = i;
                }
                if (count == 2) {
                    right = i;
                    flag = true;
                }
            }
            i++;
        }
        HashSet<String> set = new HashSet<>();
        for (int j = left + 1; j < right; j++) {
            set.addAll(treeNodeList.get(j).getLetterSetMustHas());
        }
        Set<String> newSet = simplifyLetters(set, Constant.SimplyLevel.LOW);
        for (String str : newSet) {
            {
                if (!Arrays.asList(d_MATCH_CHARACTER_LIST).contains(str)) {
                    flag = false;
                    break;
                }
            }
        }
        if (right == treeNodeList.size() - 1) {
            flag = false;
        }
        return flag;
    }

    @Deprecated
    public static boolean isWRedos(List<TreeNode> treeNodeList) {
        int left = -1;
        int right = -1;
        int count = 0;
        int i = 0;
        boolean flag = false;
        for (TreeNode child : treeNodeList) {
            String data = child.getData();
            if (data.equals("[\\w]+") || data.equals("[\\w]*") || data.equals("([\\w]*)") || data.equals("([\\w]+)") || data.equals("([\\w])*") || data.equals("([\\w])+")) {
                count++;
                if (count == 1) {
                    left = i;
                }
                if (count == 2) {
                    right = i;
                    flag = true;
                }
            }
            i++;
        }
        HashSet<String> set = new HashSet<>();
        for (int j = left + 1; j < right; j++) {
            set.addAll(treeNodeList.get(j).getLetterSetMustHas());
        }
        Set<String> newSet = simplifyLetters(set, Constant.SimplyLevel.LOW);
        for (String str : newSet) {
            {
                if (str.equals("\\-")) {
                    continue;
                }
                if (!Arrays.asList(w_MATCH_CHARACTER_LIST).contains(str)) {
                    flag = false;
                    break;
                }
            }
        }
        if (right == treeNodeList.size() - 1) {
            flag = false;
        }
        return flag;
    }

    @Deprecated
    public static boolean isSRedos(List<TreeNode> treeNodeList) {
        int left = -1;
        int right = -1;
        int count = 0;
        int i = 0;
        boolean flag = false;
        for (TreeNode child : treeNodeList) {
            String data = child.getData();
            if (data.equals("[\\s]+") || data.equals("[\\s]*") || data.equals("([\\s]*)") || data.equals("([\\s]+)") || data.equals("([\\s])*") || data.equals("([\\s])+")) {
                count++;
                if (count == 1) {
                    left = i;
                }
                if (count == 2) {
                    right = i;
                    flag = true;
                }
            }
            i++;
        }
        HashSet<String> set = new HashSet<>();
        for (int j = left + 1; j < right; j++) {
            set.addAll(treeNodeList.get(j).getLetterSetMustHas());
        }
        Set<String> newSet = simplifyLetters(set, Constant.SimplyLevel.LOW);
        for (String str : newSet) {
            {
                if (!Arrays.asList(s_MATCH_CHARACTER_LIST).contains(str)) {
                    flag = false;
                    break;
                }
            }
        }
        if (right == treeNodeList.size() - 1) {
            flag = false;
        }
        return flag;
    }
}
