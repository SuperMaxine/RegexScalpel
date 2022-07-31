package detector.Analysis;

import cn.ac.ios.Bean.Pair;
import detector.Analysis.ReDosBean.*;
import detector.Path.Path;
import detector.Tree.Nodes.*;
import detector.Tree.Tree;
import detector.Tree.TreeUtils;

import java.util.*;

import static detector.Tree.Tree.*;
import static detector.Tree.TreeUtils.*;

public class Analysis {
    private static boolean debugStep = false;
    static int maxPathLength = 10;

    public static Vector<Pair<String, RepairType>> Analysis(String regex, int repairTime) {
        Vector<Pair<String, RepairType>> result = new Vector<>();

        Tree tree = null;
        try {
            tree = new Tree(regex);
        }
        catch (Exception e) {
            System.out.println("Error: " + regex);
            return result;
        }
        // // 调试：打印语法树结构
        // System.out.println(TreeUtils.getNodeMermaidTree(tree));

        // NQ检测
        Vector<NQBean> nqBeans = NQStaticAnalysis(tree);
        // 调试：打印静态检测结果数量
        System.out.println("NQ检测结果数量：" + nqBeans.size());
        NQBean nqBean = NQDynamicAnalysis(nqBeans, tree);
        // 调试：打印检测结果
        boolean NQResult = nqBean != null;
        System.out.println("NQResult: " + NQResult);
        if (NQResult) {
            // 调试：打印漏洞位置
            TreeUtils.addMark(nqBean);
            System.out.println(tree.getRegex());
            TreeUtils.removeMark(nqBean);

            result.addAll(NQRepair(nqBean, tree));
        }

        // romove all null from result
        for (int i = 0; i < result.size() && !Thread.currentThread().isInterrupted(); i++) {
            if (result.get(i).getValue() == null) {
                result.remove(i);
                i--;
            }
        }
        if (result.size() != 0) {
            System.out.println("NQRepair: " + result);
            return result;
        }

        // QOD检测
        Vector<QODBean> qodBeans = QODStaticAnalysis(tree);
        // 调试：打印静态检测结果数量
        System.out.println("QOD检测结果数量：" + qodBeans.size());
        QODBean qodBean = QODDynamicAnalysis(qodBeans, tree);
        // 调试：打印检测结果
        boolean QODResult = qodBean != null;
        System.out.println("QODResult: " + QODResult);
        if (QODResult) {
            // 调试：打印漏洞位置
            TreeUtils.addMark(qodBean);
            System.out.println(tree.getRegex());
            TreeUtils.removeMark(qodBean);

            result.addAll(QODRepair(qodBean, tree));
        }

        // romove all null from result
        for (int i = 0; i < result.size() && !Thread.currentThread().isInterrupted(); i++) {
            if (result.get(i).getValue() == null) {
                result.remove(i);
                i--;
            }
        }
        if (result.size() != 0) {
            System.out.println("QODRepair: " + result);
            return result;
        }

        // QOA检测
        Vector<QOABean> qoaBeans = QOAStaticAnalysis(tree);
        // 调试：打印静态检测结果数量
        System.out.println("QOA检测结果数量：" + qoaBeans.size());
        QOABean qoaBean = QOADynamicAnalysis(qoaBeans, tree);
        // 调试：打印检测结果
        boolean QOAResult = qoaBean != null;
        System.out.println("QOAResult: " + QOAResult);
        if (QOAResult) {
            // 调试：打印漏洞位置
            TreeUtils.addMark(qoaBean);
            System.out.println(tree.getRegex());
            TreeUtils.removeMark(qoaBean);

            result.addAll(QOARepair(qoaBean, tree));
        }

        // romove all null from result
        for (int i = 0; i < result.size() && !Thread.currentThread().isInterrupted(); i++) {
            if (result.get(i).getValue() == null) {
                result.remove(i);
                i--;
            }
        }
        if (result.size() != 0) {
            System.out.println("QOARepair: " + result);
            return result;
        }

        // SLQ检测
        Vector<SLQBean> attackBeans = SLQStaticAnalysis(tree);
        // 调试：打印静态检测结果数量
        System.out.println("SLQ检测结果数量：" + attackBeans.size());
        SLQBean attackBean = SLQDynamicAnalysis(attackBeans, tree);
        // 调试：打印检测结果
        boolean SLQResult = attackBean != null;
        System.out.println("SLQResult: " + SLQResult);
        if (SLQResult) {
            // 调试：打印漏洞位置
            TreeUtils.addMark(attackBean);
            System.out.println(tree.getRegex());
            TreeUtils.removeMark(attackBean);

            result.addAll(SLQRepair(attackBean, tree));
        }

        // romove all null from result
        for (int i = 0; i < result.size() && !Thread.currentThread().isInterrupted(); i++) {
            if (result.get(i).getValue() == null) {
                result.remove(i);
                i--;
            }
        }
        if (result.size() != 0) {
            System.out.println("SLQRepair: " + result);
            return result;
        }

        return result;
    }

    public static Vector<NQBean> NQStaticAnalysis(Tree tree) {
        Vector<NQBean> nqBeans = new Vector<NQBean>();
        int minimum_cmax = 5;
        for (LoopNode loopNode : tree.loopNodes.values()) {
            if (Thread.currentThread().isInterrupted()) return nqBeans;
            if (loopNode.cmax < minimum_cmax) continue;
            // 判断child是否事LoopNode
            for (int i : loopNode.allChildrenNodeIds) {
                if (Thread.currentThread().isInterrupted()) return nqBeans;
                if (tree.loopNodes.containsKey(i)) { // child是LoopNode
                    if (tree.loopNodes.get(i).cmax < minimum_cmax) continue;
                    // 判断是否前后可空
                    if (TreeUtils.prefixIsNullable(loopNode, tree.loopNodes.get(i)) &&
                            TreeUtils.suffixIsNullable(loopNode, tree.loopNodes.get(i)))
                    {
                        nqBeans.add(new NQBean(loopNode, tree.loopNodes.get(i)));
                    }
                }
            }
        }
        return nqBeans;
    }

    public static NQBean NQDynamicAnalysis(Vector<NQBean> nqBeans, Tree tree) {
        for (NQBean nqBean : nqBeans) {
            if (Thread.currentThread().isInterrupted()) return null;
            // 将子正则作为中缀，父正则的前缀作为前缀，父正则的后缀作为后缀
            generatePaths(nqBean.insideLoopNode); // 1。生成内部循环节点的所有路径
            Enumerator PrefixEnumerator = new Enumerator(generatePrePath(tree.root, nqBean.outsideLoopNode).getNormalizePath(false), tree.haveAdvancedFeatures); // 2.生成外部循环节点的所有前缀
            for (Path pumpPath : nqBean.insideLoopNode.paths) {
                if (Thread.currentThread().isInterrupted()) return null;
                PrefixEnumerator.reset();
                Enumerator enumerator = new Enumerator(pumpPath.getNormalizePath(true), tree.haveAdvancedFeatures);
                AttackBean attackBean = dynamicValidate(PrefixEnumerator, enumerator, VulType.OneCounting, tree);
                if (attackBean != null) {
                    nqBean.setAttackBean(attackBean);
                    return nqBean;
                }
            }
        }
        return null;
    }

    private static Vector<Pair<String, RepairType>> NQRepair(NQBean nqBean, Tree tree) {
        Vector<Pair<String, RepairType>> result = new Vector<>();
        // 满足NQ1
        if (satisfyNQ1(nqBean)){
            result.add(new Pair<>(repairNQ1(nqBean, tree), RepairType.r1));
        }
        // 自然满足NQ2、NQ3
        // result.add("{NQ2、3:"+repairNQ2NQ3(nqBean, tree)+"}");
        result.add(new Pair<>(repairNQ2NQ3(nqBean, tree), RepairType.r2));
        result.add(new Pair<>(repairNQ2NQ3(nqBean, tree), RepairType.r3));

        return result;
    }

    private static boolean satisfyNQ1(NQBean nqBean) {
        TreeNode father = nqBean.insideLoopNode.father;
        while (father != nqBean.outsideLoopNode) {
            if (Thread.currentThread().isInterrupted()) return false;
            if (father instanceof GroupNode) {
                father = father.father;
            }
            else {
                return false;
            }
        }
        return true;
    }

    private static String repairNQ1(NQBean nqBean, Tree tree) {
        String result = "";

        // 1. 保存必要内容
        TreeNode outsideLoopNodeFather = nqBean.outsideLoopNode.father;
        int insideLoopNode_cmin = nqBean.insideLoopNode.cmin;
        int insideLoopNode_cmax = nqBean.insideLoopNode.cmax;

        // 2. 修改
        // 删除外层循环
        TreeUtils.replaceChild(nqBean.outsideLoopNode.father, nqBean.outsideLoopNode, nqBean.outsideLoopNode.child, tree);
        // 修改内层循环cmin、cmax
        nqBean.insideLoopNode.cmin = nqBean.insideLoopNode.cmin * nqBean.outsideLoopNode.cmin;
        long cmax = (long) nqBean.insideLoopNode.cmax * nqBean.outsideLoopNode.cmax;
        if (cmax > Integer.MAX_VALUE) {
            cmax = Integer.MAX_VALUE;
        }
        nqBean.insideLoopNode.cmax = (int) cmax;
        nqBean.insideLoopNode.modified = true;
        // 3. 赋值
        result = tree.getRegex();
        // 4. 恢复
        // 恢复外层循环
        TreeUtils.replaceChild(nqBean.outsideLoopNode.child.father, nqBean.outsideLoopNode.child, nqBean.outsideLoopNode, tree);
        // 恢复内层循环cmin、cmax
        nqBean.insideLoopNode.cmin = insideLoopNode_cmin;
        nqBean.insideLoopNode.cmax = insideLoopNode_cmax;
        nqBean.insideLoopNode.modified = false;

        return result;
    }

    private static String repairNQ2NQ3(NQBean nqBean, Tree tree) {
        String result = "";

        // 1. 保存必要内容
        // 2. 修改
        TreeUtils.replaceChild(nqBean.insideLoopNode.father, nqBean.insideLoopNode, nqBean.insideLoopNode.child, tree);
        // 3. 赋值
        result = tree.getRegex();
        // 4. 恢复
        TreeUtils.replaceChild(nqBean.insideLoopNode.child.father, nqBean.insideLoopNode.child, nqBean.insideLoopNode, tree);

        return result;
    }

    private static Vector<QODBean> QODStaticAnalysis(Tree tree) {
        Vector<QODBean> qodBeans = new Vector<QODBean>();
        int minimum_cmax = 5;
        for (LoopNode loopNode : tree.loopNodes.values()) {
            if (Thread.currentThread().isInterrupted()) return qodBeans;
            if (loopNode.cmax < minimum_cmax) continue;
            for (BranchNode branchNode : tree.branchNodes.values()) {
                if (Thread.currentThread().isInterrupted()) return qodBeans;
                if (loopNode.allChildrenNodeIds.contains(branchNode.id)) {
                    if (TreeUtils.prefixIsNullable(loopNode, branchNode) &&
                            TreeUtils.suffixIsNullable(loopNode, branchNode))
                    {
                        qodBeans.add(new QODBean(loopNode, branchNode));
                    }
                }
            }
        }
        return qodBeans;
    }

    public static QODBean QODDynamicAnalysis(Vector<QODBean> qodBeans, Tree tree) {
        for (QODBean qodBean : qodBeans) {
            if (Thread.currentThread().isInterrupted()) return null;
            // 将子正则作为中缀，父正则的前缀作为前缀，父正则的后缀作为后缀
            generatePathsQOD(qodBean.outsideLoopNode, maxPathLength, qodBean); // 1。生成外部循环节的所有路径，用特殊方法记录路径中的分支来源
            // 2. 挑出单纯由insideBranchNode通过outsideLoopNode的循环生成的路径
            Vector<Path> paths = new Vector<>();
            for (Path path : qodBean.outsideLoopNode.paths) {
                if (Thread.currentThread().isInterrupted()) return null;
                if (path.comeFrom != null) {
                    paths.add(path);
                }
            }
            // 3.生成外部循环节点的所有前缀
            Enumerator PrefixEnumerator = new Enumerator(generatePrePath(tree.root, qodBean.outsideLoopNode).getNormalizePath(false), tree.haveAdvancedFeatures);

            // 4. 判断QOD类型
            for (Path path : paths) {
                if (Thread.currentThread().isInterrupted()) return null;
                if (satisfyQOD1(qodBean, path, PrefixEnumerator, tree)) {
                    return qodBean;
                }
                else
                if (satisfyQOD2(qodBean, path, PrefixEnumerator, tree)) {
                    return qodBean;
                }
            }

            // // 2. 找到攻击迭代
            // Enumerator PrefixEnumerator = new Enumerator(generatePrePath(tree.root, qodBean.outsideLoopNode).getNormalizePath(false), tree.haveAdvancedFeatures); // 2.生成外部循环节点的所有前缀
            // for (Path pumpPath : paths) {
            //     PrefixEnumerator.reset();
            //     Enumerator enumerator = new Enumerator(pumpPath.getNormalizePath(true), tree.haveAdvancedFeatures);
            //     AttackBean attackBean = dynamicValidate(PrefixEnumerator, enumerator, VulType.OneCounting, tree);
            //     if (attackBean != null) {
            //         qodBean.setAttackBean(attackBean);
            //         qodBean.setAttackPath(pumpPath);
            //         qodBean.setIterations(paths);
            //         return qodBean;
            //     }
            // }
        }
        return null;
    }

    private static boolean satisfyQOD1(QODBean qodBean, Path path1, Enumerator PrefixEnumerator, Tree tree) {
        Vector<Set<Integer>> alpha1 = path1.getNormalizePath(false);
        for (Path path2 : qodBean.outsideLoopNode.paths) {
            if (Thread.currentThread().isInterrupted()) return false;
            if (path2.comeFrom == null || // 是由非branch节点生成的路径
                    path1.comeFrom.get(0) == path2.comeFrom.get(0) || // 不能是相同头部
                    alpha1.size() != path2.getPathSize()) // 必须是相同长度
            {
                continue;
            }

            // 判断重叠
            Vector<Set<Integer>> alpha2 = path2.getNormalizePath(false);
            Vector<Set<Integer>> result = new Vector<>();
            boolean overlap = true;
            for (int i = 0; i < alpha1.size(); i++) {
                if (Thread.currentThread().isInterrupted()) return false;
                // 判断alpha1和alpha2的第i位是否有交集
                Set<Integer> tmpSet = new HashSet<>();
                tmpSet.addAll(alpha1.get(i));
                if (alpha2.size() > 0) tmpSet.retainAll(alpha2.get(i));
                if (tmpSet.size() == 0) {
                    overlap = false;
                    break;
                }
                result.add(tmpSet);
            }
            if (overlap) {
                PrefixEnumerator.reset();
                Enumerator enumerator = new Enumerator(result, tree.haveAdvancedFeatures);
                AttackBean attackBean = dynamicValidate(PrefixEnumerator, enumerator, VulType.OneCounting, tree);
                if (attackBean != null) {
                    qodBean.setAttackBean(attackBean);
                    qodBean.setType(QODBean.qodType.QOD1);
                    Vector<Path> paths = new Vector<>();
                    paths.add(path1);
                    paths.add(path2);
                    qodBean.setIterations(paths);
                    qodBean.setAlpha(alpha1, alpha2);
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean satisfyQOD2(QODBean qodBean, Path path1, Enumerator PrefixEnumerator, Tree tree) {
        Vector<Set<Integer>> alpha1 = path1.getNormalizePath(false);
        for (TreeNode child : qodBean.insideBranchNode.children) {
            if (Thread.currentThread().isInterrupted()) return false;
            if (path1.comeFrom.get(0) == child.id) {
                continue;
            }
            for (Path path2 : child.paths) {
                if (Thread.currentThread().isInterrupted()) return false;
                if (path2.getPathSize() < alpha1.size()) {
                    continue;
                }
                // 判断重叠(path2的尾部与path1重叠)
                Vector<Set<Integer>> alpha2 = path2.getNormalizePath(false);
                Vector<Set<Integer>> result = new Vector<>();
                boolean overlap = true;
                for (int i = alpha1.size() - 1, j = alpha2.size() - 1; i >= 0 && j >=0; i--, j--) {
                    if (Thread.currentThread().isInterrupted()) return false;
                    // 判断alpha1的第i位和alpha2的第j位是否有交集
                    Set<Integer> tmpSet = new HashSet<>();
                    tmpSet.addAll(alpha1.get(i));
                    tmpSet.retainAll(alpha2.get(j));
                    if (tmpSet.size() == 0) {
                        overlap = false;
                        break;
                    }
                    result.add(tmpSet);
                }

                if (overlap) {
                    PrefixEnumerator.reset();
                    Enumerator enumerator = new Enumerator(alpha2, tree.haveAdvancedFeatures);
                    AttackBean attackBean = dynamicValidate(PrefixEnumerator, enumerator, VulType.OneCounting, tree);
                    if (attackBean != null) {
                        qodBean.setAttackBean(attackBean);
                        qodBean.setType(QODBean.qodType.QOD2);
                        Vector<Path> paths = new Vector<>();
                        paths.add(path1);
                        qodBean.setIterations(paths);
                        qodBean.setRp(child);
                        qodBean.setAlpha(alpha1, alpha2);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static Vector<Pair<String, RepairType>> QODRepair(QODBean qodBean, Tree tree) {
        Vector<Pair<String, RepairType>> result = new Vector<>();

        // 根据各个模板进行修复
        if (qodBean.type == QODBean.qodType.QOD1) {
            // repair_4：结果不一定正确
            result.addAll(repair4(qodBean, tree));

            // repair_5
            if (qodBean.iterations.get(0).comeFrom.size() > 1) {
                result.add(new Pair<>(repair5(qodBean, tree), RepairType.r5));
            }

            // repair_6
            if (qodBean.iterations.get(1).comeFrom.size() > 1) {
                result.add(new Pair<>(repair6(qodBean, tree), RepairType.r6));
            }

            // repair_7
            result.add(new Pair<>(repair7(qodBean, tree), RepairType.r7));

            // repair_8
            result.add(new Pair<>(repair8(qodBean, tree), RepairType.r8));

            // repair_9
            if (qodBean.alpha1.size() == 1) { //scs(α1)
                Set<Integer> sigma_a1 = new HashSet<>();
                for (Set<Integer> set : qodBean.alpha1){
                    if (Thread.currentThread().isInterrupted()) return result;
                    sigma_a1.addAll(set);
                }
                Set<Integer> first_rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(1).comeFrom.get(0)).getFirst();
                sigma_a1.removeAll(first_rq1);
                if (sigma_a1.size() > 0) {
                    result.add(new Pair<>(repair9(qodBean, tree, sigma_a1), RepairType.r9));
                }
            }

            // repair_10
            if (qodBean.alpha2.size() == 1) { //scs(α1)
                Set<Integer> sigma_a2 = new HashSet<>();
                for (Set<Integer> set : qodBean.alpha2){
                    if (Thread.currentThread().isInterrupted()) return result;
                    sigma_a2.addAll(set);
                }
                Set<Integer> first_rp1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0)).getFirst();
                sigma_a2.removeAll(first_rp1);
                if (sigma_a2.size() > 0) {
                    result.add(new Pair<>(repair10(qodBean, tree, sigma_a2), RepairType.r9));
                }
            }
        }
        else if (qodBean.type == QODBean.qodType.QOD2) {
            // repair_6
            if (qodBean.iterations.get(0).comeFrom.size() > 1) {
                result.add(new Pair<>(repair6(qodBean, tree), RepairType.r6));
            }

            // repair_11
            result.add(new Pair<>(repair11(qodBean, tree), RepairType.r11));

            // repair_12
            result.add(new Pair<>(repair12(qodBean, tree), RepairType.r12));

            // repair_13
            if (qodBean.alpha1.size() == 1) { //scs(α1)
                Set<Integer> sigma_a1 = new HashSet<>();
                for (Set<Integer> set : qodBean.alpha1) {
                    if (Thread.currentThread().isInterrupted()) return result;
                    sigma_a1.addAll(set);
                }
                Set<Integer> first_rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0)).getFirst();
                sigma_a1.removeAll(first_rq1);
                if (sigma_a1.size() > 0) {
                    result.add(new Pair<>(repair13(qodBean, tree, sigma_a1), RepairType.r13));
                }
            }

            // repair_14
            TreeNode ru = rpEqualru(qodBean.rp);
            if (ru != null && ru instanceof CharsetNode) {
                Set<Integer> sigma_ru = new HashSet<>();
                sigma_ru.addAll(((CharsetNode) ru).getCharset());
                Set<Integer> first_rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0)).getFirst();
                sigma_ru.removeAll(first_rq1);
                if (sigma_ru.size() > 0) {
                    result.add(new Pair<>(repair14(qodBean, tree, sigma_ru), RepairType.r14));
                }
            }

        }


        return result;
    }

    private static TreeNode rpEqualru(TreeNode rp) {
        // 从左到右遍历，跳过空节点（lookaround、锚点等），找到第一个非空节点，且是Loop节点
        TreeNode r = findRu_left(rp);
        if (!(r instanceof LoopNode)) {
            return null;
        }

        // 从右到左遍历，跳过空节点（lookaround、锚点等），找到第一个非空节点，且是同一个Loop节点
        TreeNode r_ = findRu_right(rp);
        if (r_ != r) {
            return null;
        }

        return ((LoopNode) r).child;
    }

    private static TreeNode findRu_left(TreeNode rp) {
        if (rp instanceof LoopNode) {
            return (LoopNode) rp;
        }
        else if (rp instanceof LookaroundNode || rp instanceof WordBoundaryNode || rp instanceof PositionNode) {
            return new LeafNode(-1, null);
        }
        else if (rp instanceof GroupNode) {
            return findRu_left(((GroupNode) rp).child);
        }
        else if (rp instanceof ConnectNode) {
            TreeNode tmp = findRu_left(((ConnectNode) rp).left);
            if (tmp instanceof LoopNode) {
                return tmp;
            }
            else if (tmp == null) {
                return null;
            }
            else {
                return findRu_left(((ConnectNode) rp).right);
            }
        }
        else if (rp instanceof BranchNode) {
            for (TreeNode child : ((BranchNode) rp).children) {
                if (Thread.currentThread().isInterrupted()) return null;
                TreeNode tmp = findRu_left(child);
                if (tmp instanceof LoopNode) {
                    return tmp;
                }
            }
            return null;
        }
        else {
            return null;
        }
    }

    private static TreeNode findRu_right(TreeNode rp) {
        if (rp instanceof LoopNode) {
            return (LoopNode) rp;
        }
        else if (rp instanceof LookaroundNode || rp instanceof WordBoundaryNode || rp instanceof PositionNode) {
            return new LeafNode(-1, null);
        }
        else if (rp instanceof GroupNode) {
            return findRu_right(((GroupNode) rp).child);
        }
        else if (rp instanceof ConnectNode) {
            TreeNode tmp = findRu_right(((ConnectNode) rp).right);
            if (tmp instanceof LoopNode) {
                return tmp;
            }
            else if (tmp == null) {
                return null;
            }
            else {
                return findRu_right(((ConnectNode) rp).left);
            }
        }
        else if (rp instanceof BranchNode) {
            for (TreeNode child : ((BranchNode) rp).children) {
                if (Thread.currentThread().isInterrupted()) return null;
                TreeNode tmp = findRu_right(child);
                if (tmp instanceof LoopNode) {
                    return tmp;
                }
            }
            return null;
        }
        else {
            return null;
        }
    }

    private static Vector<Pair<String, RepairType>> repair4(QODBean qodBean, Tree tree) {
        Vector<Pair<String, RepairType>> result = new Vector<>();

        // 1. 保存必要内容
        TreeNode rp1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0)); // 删除节点数少的那个
        if (qodBean.iterations.get(0).comeFrom.size() > qodBean.iterations.get(1).comeFrom.size()) {
            rp1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(1).comeFrom.get(0));
        }
        // 2. 修改
        // 从insideBranchNode中删除rp1
        qodBean.insideBranchNode.removeChild(rp1);
        // 3. 赋值
        result.add(new Pair<>(tree.getRegex(), RepairType.r4));
        // 4. 恢复
        qodBean.insideBranchNode.addChild(rp1);

        // // 5. 修改
        // // 从insideBranchNode中删除rp2
        // qodBean.insideBranchNode.removeChild(rp2);
        // // 6. 赋值
        // result.add(new Pair<>(tree.getRegex(), RepairType.r4));
        // // 7. 恢复
        // qodBean.insideBranchNode.addChild(rp2);

        return result;
    }

    private static String repair5(QODBean qodBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rp1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0));
        TreeNode rp2 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(1));

        // 2. 修改
        // 2.1 新建lookaround节点及connect节点
        setPhi(rp2, true);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, rp2);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), rp1, lookaroundNode);
        // 2.2 删除原有节点并替换为新节点
        qodBean.insideBranchNode.removeChild(rp1);
        qodBean.insideBranchNode.addChild(connectNode);
        // 3. 赋值
        result = tree.getRegex();
        // 4. 恢复
        setPhi(rp2, false);
        qodBean.insideBranchNode.removeChild(connectNode);
        qodBean.insideBranchNode.addChild(rp1);


        return result;
    }

    private static String repair6(QODBean qodBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(1).comeFrom.get(0));
        TreeNode rq2 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(1).comeFrom.get(1));

        // 2. 修改
        // 2.1 获取phi_rq2
        String phi_rq2 = "";
        setPhi(rq2, true);
        generateRegex(rq2);
        phi_rq2 = rq2.regex;
        setPhi(rq2, false);
        // 2.2 新建lookaround节点及connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rq2);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), rq1, lookaroundNode);
        // 2.3 删除原有节点并替换为新节点
        qodBean.insideBranchNode.removeChild(rq1);
        qodBean.insideBranchNode.addChild(connectNode);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        qodBean.insideBranchNode.removeChild(connectNode);
        qodBean.insideBranchNode.addChild(rq1);

        return result;
    }

    private static String repair7(QODBean qodBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rp1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0));
        TreeNode rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(1).comeFrom.get(0));

        // 2. 修改
        // 2.1 获取phi_rq1
        String phi_rq1 = "";
        setPhi(rq1, true);
        generateRegex(rq1);
        phi_rq1 = rq1.regex;
        setPhi(rq1, false);
        // 2.2 新建lookaround节点及connect节点
        // // 按照文章中的修复有误，不应为α2，而应为rq1
        // String αlpha2 = "";
        // for (int childID : qodBean.iterations.get(1).comeFrom) {
        //     TreeNode child = qodBean.insideBranchNode.getChildByID(childID);
        //     setPhi(child, true);
        //     generateRegex(child);
        //     αlpha2 += child.regex;
        //     setPhi(child, false);
        // }
        // SliceNode lookaroundNode = new SliceNode(tree.getCount(), "(?!" + αlpha2 + ")");
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rq1);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), lookaroundNode, rp1);
        // 2.3 删除原有节点并替换为新节点
        qodBean.insideBranchNode.removeChild(rp1);
        qodBean.insideBranchNode.addChild(connectNode);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        qodBean.insideBranchNode.removeChild(connectNode);
        qodBean.insideBranchNode.addChild(rp1);

        return result;
    }

    private static String repair8(QODBean qodBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rp1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0));
        TreeNode rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(1).comeFrom.get(0));

        // 2. 修改
        // 2.1 获取phi_rp1
        String phi_rp1 = "";
        setPhi(rp1, true);
        generateRegex(rp1);
        phi_rp1 = rp1.regex;
        setPhi(rp1, false);
        // 2.2 新建lookaround节点及connect节点
        // // 按照文章中的修复有误，不应为α1，而应为rp1
        // String αlpha1 = "";
        // for (int childID : qodBean.iterations.get(0).comeFrom) {
        //     TreeNode child = qodBean.insideBranchNode.getChildByID(childID);
        //     setPhi(child, true);
        //     generateRegex(child);
        //     αlpha1 += child.regex;
        //     setPhi(child, false);
        // }
        // SliceNode lookaroundNode = new SliceNode(tree.getCount(), "(?!" + αlpha1 + ")");
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rp1);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), lookaroundNode, rq1);
        // 2.3 删除原有节点并替换为新节点
        qodBean.insideBranchNode.removeChild(rq1);
        qodBean.insideBranchNode.addChild(connectNode);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        qodBean.insideBranchNode.removeChild(connectNode);
        qodBean.insideBranchNode.addChild(rq1);

        return result;
    }

    private static String repair9(QODBean qodBean, Tree tree, Set<Integer> sigma_a1_minus_first_rq1) {
        String result = "";
        // 1. 保存必要信息
        TreeNode rp1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0));
        assert rp1 instanceof ContentNode;

        // 2. 修复
        // 2.1 新建节点类
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_a1_minus_first_rq1, theta(sigma_a1_minus_first_rq1));
        // 2.2 删除原有节点并替换为新节点
        if (rp1 instanceof CharsetNode) {
            TreeUtils.replaceChild(rp1.father, rp1, charsetNode, tree);
        }
        else if (rp1 instanceof SliceNode) {
            throw new RuntimeException("repair9: rp1 is SliceNode");
        }

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(charsetNode.father, charsetNode, rp1, tree);

        return result;
    }

    private static String repair10(QODBean qodBean, Tree tree, Set<Integer> sigma_a2_minus_first_rp1) {
        String result = "";
        // 1. 保存必要信息
        TreeNode rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(1).comeFrom.get(0));
        assert rq1 instanceof ContentNode;

        // 2. 修复
        // 2.1 新建节点类
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_a2_minus_first_rp1, theta(sigma_a2_minus_first_rp1));
        // 2.2 删除原有节点并替换为新节点
        if (rq1 instanceof CharsetNode) {
            TreeUtils.replaceChild(rq1.father, rq1, charsetNode, tree);
        }
        else if (rq1 instanceof SliceNode) {
            throw new RuntimeException("repair9: rp1 is SliceNode");
        }

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(charsetNode.father, charsetNode, rq1, tree);

        return result;
    }

    private static String repair11(QODBean qodBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rp = qodBean.rp;

        // 2. 修改
        // 2.1 获取phi(alpha1)
        String phi_alpha1 = "";
        for (int rqi_id : qodBean.iterations.get(0).comeFrom) {
            if (Thread.currentThread().isInterrupted()) return result;
            TreeNode rqi = qodBean.insideBranchNode.getChildByID(rqi_id);
            setPhi(rqi, true);
            generateRegex(rqi);
            phi_alpha1 += rqi.regex;
        }
        setPhi(qodBean.insideBranchNode, false);
        // 2.2 新建lookaround节点及connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_alpha1);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.NotBehind, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), rp, lookaroundNode);
        // 2.3 删除原有节点并替换为新节点
        qodBean.insideBranchNode.removeChild(rp);
        qodBean.insideBranchNode.addChild(connectNode);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        qodBean.insideBranchNode.removeChild(connectNode);
        qodBean.insideBranchNode.addChild(rp);

        return result;
    }

    private static String repair12(QODBean qodBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0));

        // 2. 修改
        // 2.1 获取phi(rp)
        String phi_rp = "";
        setPhi(qodBean.rp, true);
        generateRegex(qodBean.rp);
        phi_rp = qodBean.rp.regex;
        setPhi(qodBean.insideBranchNode, false);
        // 2.2 新建lookaround节点及connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rp);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.NotBehind, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), rq1, lookaroundNode);
        // 2.3 删除原有节点并替换为新节点
        qodBean.insideBranchNode.removeChild(rq1);
        qodBean.insideBranchNode.addChild(connectNode);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        qodBean.insideBranchNode.removeChild(connectNode);
        qodBean.insideBranchNode.addChild(rq1);

        return result;
    }

    private static String repair13(QODBean qodBean, Tree tree, Set<Integer> sigma_a1_minus_first_rp) { // 因为a1经过scs检验，所以sigma_a1与sigma_rq1相同
        // 1. 保存必要内容
        TreeNode rq1 = qodBean.insideBranchNode.getChildByID(qodBean.iterations.get(0).comeFrom.get(0));

        // 2. 修改
        // 2.1 新建节点类
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_a1_minus_first_rp, theta(sigma_a1_minus_first_rp));
        // 2.2 删除原有节点并替换为新节点
        if (rq1 instanceof CharsetNode) {
            TreeUtils.replaceChild(rq1.father, rq1, charsetNode, tree);
        }
        else if (rq1 instanceof SliceNode) {
            throw new RuntimeException("repair13: rp1 is SliceNode");
        }

        // 3. 赋值
        String result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(charsetNode.father, charsetNode, rq1, tree);

        return result;
    }

    private static String repair14(QODBean qodBean, Tree tree, Set<Integer> sigma_ru_minus_first_rq1) {
        // 1. 保存必要内容
        TreeNode rp = qodBean.rp;

        // 2. 修改
        // 2.1 新建节点类
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_ru_minus_first_rq1, theta(sigma_ru_minus_first_rq1));
        // 2.2 删除原有节点并替换为新节点
        if (rp instanceof CharsetNode) {
            TreeUtils.replaceChild(rp.father, rp, charsetNode, tree);
        }
        else if (rp instanceof SliceNode) {
            throw new RuntimeException("repair14: rp is SliceNode");
        }

        // 3. 赋值
        String result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(charsetNode.father, charsetNode, rp, tree);

        return result;
    }


    private static Vector<QOABean> QOAStaticAnalysis(Tree tree) {
        Vector<QOABean> qoaBeans = new Vector<QOABean>();
        int minimum_cmax = 0;

        Set<Integer> lookaroundNodesChildren = new HashSet<Integer>();
        for (LookaroundNode lookaroundNode : tree.lookaroundNodes.values()) {
            if (Thread.currentThread().isInterrupted()) return qoaBeans;
            lookaroundNodesChildren.addAll(lookaroundNode.allChildrenNodeIds);
        }

        // Convert tree.loopNodes from HashMap<Integer, LoopNode> to Vector<LoopNode>
        Vector<LoopNode> loopNodes = new Vector<LoopNode>();
        for (LoopNode loopNode : tree.loopNodes.values()) {
            if (Thread.currentThread().isInterrupted()) return qoaBeans;
                    loopNodes.add(loopNode);
        }

        for (int i = 0 ; i < loopNodes.size() ; i++) {
            if (Thread.currentThread().isInterrupted()) return qoaBeans;
                    LoopNode r1 = loopNodes.get(i);
            if (r1.cmax < minimum_cmax || lookaroundNodesChildren.contains(r1.id)) continue;
            for (int j = i + 1 ; j < loopNodes.size() ; j++) {
                if (Thread.currentThread().isInterrupted()) return qoaBeans;
                        LoopNode r2 = loopNodes.get(j);
                // 判断r2是否为r1的子节点或r1等于r2，如果是则跳过
                if (TreeUtils.isChild(r1, r2) || TreeUtils.isChild(r2, r1) || r1.id == r2.id) continue;
                if (r2.cmax < minimum_cmax || lookaroundNodesChildren.contains(r1.id)) continue;
                // 判断是否为QOA1或QOA2
                LinkNode commonFather = getCommonFather(r1, r2);
                if (commonFather != null && !(commonFather instanceof BranchNode)) {
                    assert commonFather instanceof ConnectNode;
                    ConnectNode connectNode = (ConnectNode) commonFather;
                    LoopNode leftnode = null;
                    LoopNode rightnode = null;
                    // 调整r1、r2的顺序，使其中一个为左节点，另一个为右节点
                    if (!node1IsLeftOfNode2(r1, r2, connectNode)) {
                        leftnode = r2;
                        rightnode = r1;
                    }
                    else {
                        leftnode = r1;
                        rightnode = r2;
                    }

                    // 判断是否为QOA2
                    if (satisfyQOA2(leftnode, rightnode, connectNode)) { // 满足QOA2条件，说明中缀可空，但未判断中缀是否存在内容
                        QOABean tmp = new QOABean(leftnode, rightnode, QOABean.qoaType.QOA1);
                        tmp.commonFather = connectNode;
                        qoaBeans.add(tmp);

                    }
                    else {
                        // 判断是否为QOA3、QOA4、QOA5
                        LoopNode outsideLoopNode = getNearestAncestorLoopNode(commonFather);
                        if (outsideLoopNode == null) continue;
                        if (satisfyQOA3(leftnode, rightnode, outsideLoopNode)) {
                            QOABean qoa3 = new QOABean(leftnode, rightnode, QOABean.qoaType.QOA3);
                            qoa3.setOutsideLoopNode(outsideLoopNode);
                            qoaBeans.add(qoa3);
                        }
                    }
                }
            }
        }
        return qoaBeans;
    }

    private static boolean satisfyQOA3(LoopNode r1, LoopNode r2, LoopNode outsideLoopNode) {
        return (prefixIsNullable(outsideLoopNode, r1) && suffixIsNullable(outsideLoopNode, r2));
    }

    private static boolean satisfyQOA2(LoopNode r1, LoopNode r2, ConnectNode commonFather) {
        return (suffixIsNullable(commonFather, r1) && prefixIsNullable(commonFather, r2));
    }

    private static QOABean QOADynamicAnalysis(Vector<QOABean> qoaBeans, Tree tree) {
        for (QOABean qoaBean : qoaBeans) {
            if (Thread.currentThread().isInterrupted()) return null;
            // 对QOA1和QOA2的检测
            if (qoaBean.type == QOABean.qoaType.QOA1 || qoaBean.type == QOABean.qoaType.QOA2) {
                Enumerator prefixEnumerator = new Enumerator(generatePrePath(tree.root, qoaBean.r1).getNormalizePath(false), tree.haveAdvancedFeatures);
                generatePaths(qoaBean.r1);
                generatePaths(qoaBean.r2);
                if (qoaBean.r1.paths.size()==0 || qoaBean.r2.paths.size()==0) continue;
                if (qoaBean.r1.paths.get(qoaBean.r1.paths.size() - 1).getPathSize() < qoaBean.r2.paths.get(qoaBean.r2.paths.size() - 1).getPathSize()) {
                    generatePaths(qoaBean.r1, qoaBean.r2.paths.get(qoaBean.r2.paths.size() - 1).getPathSize());
                }
                else {
                    generatePaths(qoaBean.r2, qoaBean.r1.paths.get(qoaBean.r1.paths.size() - 1).getPathSize());
                }
                for (Path r1Path : qoaBean.r1.paths) {
                    if (Thread.currentThread().isInterrupted()) return null;
                    for (Path r2Path : qoaBean.r2.paths) {
                        if (Thread.currentThread().isInterrupted()) return null;
                        if (r1Path.getPathSize() != r2Path.getPathSize()) continue;
                        Vector<Set<Integer>> path1 = r1Path.getNormalizePath(true);
                        Vector<Set<Integer>> path2 = r2Path.getNormalizePath(true);
                        Vector<Set<Integer>> pumpPath = new Vector<Set<Integer>>();
                        // 寻找path1和path2是否每一位都存在交集
                        boolean isIntersect = true;
                        for (int i = 0; i < path1.size(); i++) {
                            if (Thread.currentThread().isInterrupted()) return null;
                            Set<Integer> set1 = path1.get(i);
                            Set<Integer> set2 = path2.get(i);
                            if (set1.size() == 0 || set2.size() == 0) continue;
                            Set<Integer> tmp = new HashSet<Integer>();
                            tmp.addAll(set1);
                            tmp.retainAll(set2);
                            if (tmp.size() == 0) {
                                isIntersect = false;
                                break;
                            }
                            pumpPath.add(tmp);
                        }
                        if (isIntersect) {
                            prefixEnumerator.reset();
                            Enumerator pumpEnumerator = new Enumerator(pumpPath, tree.haveAdvancedFeatures);
                            AttackBean attackBean = dynamicValidate(prefixEnumerator, pumpEnumerator, VulType.POA, tree);
                            if (attackBean != null) {
                                qoaBean.setAttackBean(attackBean);
                                return qoaBean;
                            }
                        }
                    }
                }
            }

            // 对QOA3的检测
            else if (qoaBean.type == QOABean.qoaType.QOA3) {
                Enumerator prefixEnumerator = new Enumerator(generatePrePath(tree.root, qoaBean.outsideLoopNode).getNormalizePath(false), tree.haveAdvancedFeatures);
                generatePaths(qoaBean.outsideLoopNode);
                for (Path pumpPath : qoaBean.outsideLoopNode.paths) {
                    if (Thread.currentThread().isInterrupted()) return null;
                    Vector<Set<Integer>> pumpPath1 = pumpPath.getNormalizePath(true);
                    Enumerator pumpEnumerator = new Enumerator(pumpPath1, tree.haveAdvancedFeatures);
                    AttackBean attackBean = dynamicValidate(prefixEnumerator, pumpEnumerator, VulType.POA, tree);
                    if (attackBean != null) {
                        qoaBean.setAttackBean(attackBean);
                        return qoaBean;
                    }
                }
            }
        }
        return null;
    }

    private static Vector<Pair<String, RepairType>> QOARepair(QOABean qoaBean, Tree tree) {
        Vector<Pair<String, RepairType>> result = new Vector<>();

        if (qoaBean.type == QOABean.qoaType.QOA1) {
            generateRegex(qoaBean.commonFather);
            if (qoaBean.r1.child.regex == qoaBean.r2.child.regex) {
                result.add(new Pair<>(repair15(qoaBean, tree), RepairType.r15));
            }

            // repair16
            result.add(new Pair<>(repair16(qoaBean, tree), RepairType.r16));

            // repair17
            result.add(new Pair<>(repair17(qoaBean, tree), RepairType.r17));

            // repair18
            result.add(new Pair<>(repair18(qoaBean, tree, 500), RepairType.r18));

            // repair19 && repair21
            // if (qoaBean.r1.child instanceof CharsetNode) { // scs(rp)
            Vector<TreeNode> tmpNodeList = new Vector<>();
            tmpNodeList.add(qoaBean.r1.child);
            CharsetNode rp = scs(tmpNodeList, tree);
            if (rp != null) { // scs(rp)
                Set<Integer> sigma_rp = new HashSet<>();
                sigma_rp.addAll(rp.getCharset());
                Set<Integer> first_rq = new HashSet<>();
                first_rq.addAll(qoaBean.r2.child.getFirst());
                sigma_rp.removeAll(first_rq); // sigma_rp = sigma_rp \ first_rq
                if (sigma_rp.size() > 0) {
                    result.add(new Pair<>(repair19(qoaBean, tree, sigma_rp), RepairType.r19));
                    if (qoaBean.r1.cmin >=1) {
                        result.add(new Pair<>(repair21(qoaBean, tree, sigma_rp), RepairType.r21));
                    }
                }
            }

            // repair20
            // if (qoaBean.r2.child instanceof CharsetNode) { // scs(rq)
            tmpNodeList = new Vector<>();
            tmpNodeList.add(qoaBean.r2);
            CharsetNode rq = scs(tmpNodeList, tree);
            if (rq != null) { // scs(rq)
                Set<Integer> sigma_rq = new HashSet<>();
                sigma_rq.addAll(rq.getCharset());
                Set<Integer> first_rp = new HashSet<>();
                first_rp.addAll(qoaBean.r1.child.getFirst());
                sigma_rq.removeAll(first_rp); // sigma_rq = sigma_rq \ first_rp
                if (sigma_rq.size() > 0) {
                    result.add(new Pair<>(repair20(qoaBean, tree, sigma_rq), RepairType.r20));
                    if (qoaBean.r2.cmin >=1) {
                        result.add(new Pair<>(repair22(qoaBean, tree, sigma_rq), RepairType.r22));
                    }
                }
            }

        }
        else if (qoaBean.type == QOABean.qoaType.QOA2) {
            // repair18
            result.add(new Pair<>(repair18(qoaBean, tree, 500), RepairType.r18));

            // repair27
            result.add(new Pair<>(repair27(qoaBean, tree), RepairType.r27));
        }
        else if (qoaBean.type == QOABean.qoaType.QOA3) {
            // repair19 & repair25
            // if (qoaBean.r1.child instanceof CharsetNode) { // scs(rp)
            Vector<TreeNode> tmpNodeList = new Vector<>();
            tmpNodeList.add(qoaBean.r1.child);
            CharsetNode rp = scs(tmpNodeList, tree);
            if (rp != null) { // scs(rp)
                Set<Integer> sigma_rp = new HashSet<>();
                sigma_rp.addAll(((CharsetNode)qoaBean.r1.child).getCharset());
                Set<Integer> first_rq = new HashSet<>();
                first_rq.addAll(qoaBean.r2.child.getFirst());
                sigma_rp.removeAll(first_rq); // sigma_rp = sigma_rp \ first_rq
                if (sigma_rp.size() > 0) {
                    result.add(new Pair<>(repair19(qoaBean, tree, sigma_rp), RepairType.r19));
                    if (qoaBean.r1.cmin >=1) {
                        result.add(new Pair<>(repair25(qoaBean, tree, sigma_rp), RepairType.r25));
                    }
                }
            }

            // repair20 & repair26
            // if (qoaBean.r2.child instanceof CharsetNode) { // scs(rq)
            tmpNodeList = new Vector<>();
            tmpNodeList.add(qoaBean.r2);
            CharsetNode rq = scs(tmpNodeList, tree);
            if (rq != null) { // scs(rq)
                Set<Integer> sigma_rq = new HashSet<>();
                sigma_rq.addAll(((CharsetNode)qoaBean.r2.child).getCharset());
                Set<Integer> first_rp = new HashSet<>();
                first_rp.addAll(qoaBean.r1.child.getFirst());
                sigma_rq.removeAll(first_rp); // sigma_rq = sigma_rq \ first_rp
                if (sigma_rq.size() > 0) {
                    result.add(new Pair<>(repair20(qoaBean, tree, sigma_rq), RepairType.r20));
                    if (qoaBean.r2.cmin >=1) {
                        result.add(new Pair<>(repair26(qoaBean, tree, sigma_rq), RepairType.r26));
                    }
                }
            }

            // repair23
            result.add(new Pair<>(repair23(qoaBean, tree), RepairType.r23));

            // repair24
            result.add(new Pair<>(repair24(qoaBean, tree), RepairType.r24));
        }
        else if (qoaBean.type == QOABean.qoaType.QOA4) {
            result.add(new Pair<>(repair28(qoaBean, tree), RepairType.r24));
        }
        else if (qoaBean.type == QOABean.qoaType.QOA5) {
            result.add(new Pair<>(repair29(qoaBean, tree), RepairType.r24));
        }

        return result;
    }

    private static String repair15(QOABean qoaBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        int r1_min = qoaBean.r1.cmin;
        int r1_max = qoaBean.r1.cmax;

        // 2. 修改
        qoaBean.r1.cmin = qoaBean.r1.cmin + qoaBean.r2.cmin;
        qoaBean.r1.cmax = qoaBean.r1.cmax + qoaBean.r2.cmax;
        qoaBean.r1.modified = true;
        replaceChild(qoaBean.commonFather.father, qoaBean.commonFather, qoaBean.r1, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        qoaBean.r1.cmin = r1_min;
        qoaBean.r1.cmax = r1_max;
        replaceChild(qoaBean.commonFather.father, qoaBean.r1, qoaBean.commonFather, tree);

        return result;
    }

    private static String repair16(QOABean qoaBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rq = qoaBean.r2.child;
        TreeNode r1_father = qoaBean.r1.father;

        // 2. 修改
        // 2.1 获取phi(rq)
        String phi_rq = "";
        setPhi(rq, true);
        generateRegex(rq);
        phi_rq = rq.regex;
        setPhi(rq, false);
        // 2.2 新建lookaround节点及connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rq);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.NotBehind, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), qoaBean.r1, lookaroundNode);
        // 2.3 替换原有节点
        TreeUtils.replaceChild(r1_father, qoaBean.r1, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(connectNode.father, connectNode, qoaBean.r1, tree);

        return result;
    }

    private static String repair17(QOABean qoaBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rp = qoaBean.r1.child;
        TreeNode r2_father = qoaBean.r2.father;

        // 2. 修改
        // 2.1 获取phi(rp)
        String phi_rp = "";
        setPhi(rp, true);
        generateRegex(rp);
        phi_rp = rp.regex;
        setPhi(rp, false);
        // 2.2 新建lookaround节点及connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rp);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), lookaroundNode, qoaBean.r2);
        // 2.3 替换原有节点
        TreeUtils.replaceChild(r2_father, qoaBean.r2, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(connectNode.father, connectNode, qoaBean.r2, tree);

        return result;
    }

    private static String repair18(QOABean qoaBean, Tree tree, int n_u) {
        String result = "";
        // 1. 保存必要内容
        int r1_max = qoaBean.r1.cmax;
        int r2_max = qoaBean.r2.cmax;

        // 2. 修改
        qoaBean.r1.cmax = r2_max > n_u ? n_u : r2_max;
        qoaBean.r2.cmax = r1_max > n_u ? n_u : r1_max;
        qoaBean.r1.modified = true;
        qoaBean.r2.modified = true;

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        qoaBean.r1.cmax = r1_max;
        qoaBean.r2.cmax = r2_max;
        qoaBean.r1.modified = false;
        qoaBean.r2.modified = false;

        return result;
    }

    private static String repair19(QOABean qoaBean, Tree tree, Set<Integer> sigma_rp_minus_first_rq) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rp = qoaBean.r1.child;

        // 2. 修改
        // 2.1 新建CharsetNode
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rp_minus_first_rq, theta(sigma_rp_minus_first_rq));
        // 2.2 替换原有节点
        TreeUtils.replaceChild(rp.father, rp, charsetNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(charsetNode.father, charsetNode, rp, tree);

        return result;
    }

    private static String repair20(QOABean qoaBean, Tree tree, Set<Integer> sigma_rq_minus_first_rp) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rq = qoaBean.r2.child;

        // 2. 修改
        // 2.1 新建CharsetNode
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rq_minus_first_rp, theta(sigma_rq_minus_first_rp));
        // 2.2 替换原有节点
        TreeUtils.replaceChild(rq.father, rq, charsetNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(charsetNode.father, charsetNode, rq, tree);

        return result;
    }

    private static String repair21(QOABean qoaBean, Tree tree, Set<Integer> sigma_rp) {
        String result = "";
        // 1. 保存必要内容
        int r1_min = qoaBean.r1.cmin;
        int r1_max = qoaBean.r1.cmax;

        // 2. 修改
        // 2.1 修改rp的cmin和cmax
        qoaBean.r1.cmin = qoaBean.r1.cmin - 1;
        qoaBean.r1.cmax = qoaBean.r1.cmax - 1;
        qoaBean.r1.modified = true;
        // 2.2 新建CharsetNode
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rp, theta(sigma_rp));
        // 2.3 新建connectNode
        ConnectNode connectNode = new ConnectNode(tree.getCount(), qoaBean.r1, charsetNode);
        // 2.4 替换原有节点
        TreeUtils.replaceChild(qoaBean.r1.father, qoaBean.r1, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(connectNode.father, connectNode, qoaBean.r1, tree);
        qoaBean.r1.cmin = r1_min;
        qoaBean.r1.cmax = r1_max;
        qoaBean.r1.modified = false;

        return result;
    }

    private static String repair22(QOABean qoaBean, Tree tree, Set<Integer> sigma_rq) {
        String result = "";
        // 1. 保存必要内容
        int r2_min = qoaBean.r2.cmin;
        int r2_max = qoaBean.r2.cmax;

        // 2. 修改
        // 2.1 修改rq的cmin和cmax
        qoaBean.r2.cmin = qoaBean.r2.cmin - 1;
        qoaBean.r2.cmax = qoaBean.r2.cmax - 1;
        qoaBean.r2.modified = true;
        // 2.2 新建CharsetNode
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rq, theta(sigma_rq));
        // 2.3 新建connectNode
        ConnectNode connectNode = new ConnectNode(tree.getCount(), charsetNode, qoaBean.r2);
        // 2.4 替换原有节点
        TreeUtils.replaceChild(qoaBean.r2.father, qoaBean.r2, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(connectNode.father, connectNode, qoaBean.r2, tree);
        qoaBean.r2.cmin = r2_min;
        qoaBean.r2.cmax = r2_max;
        qoaBean.r2.modified = false;

        return result;
    }

    private static String repair23(QOABean qoaBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rq = qoaBean.r2.child;

        // 2. 修改
        // 2.1 获取phi(rq)
        String phi_rq = "";
        setPhi(rq, true);
        generateRegex(rq);
        phi_rq = rq.regex;
        setPhi(rq, false);
        // 2.2 新建lookaround节点及connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rq);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), lookaroundNode, qoaBean.r1);
        // 2.3 替换原有节点
        TreeUtils.replaceChild(qoaBean.r1.father, qoaBean.r1, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(connectNode.father, connectNode, qoaBean.r1, tree);

        return result;
    }

    private static String repair24(QOABean qoaBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容
        TreeNode rp = qoaBean.r1.child;

        // 2. 修改
        // 2.1 获取phi(rp)
        String phi_rp = "";
        setPhi(rp, true);
        generateRegex(rp);
        phi_rp = rp.regex;
        setPhi(rp, false);
        // 2.2 新建lookaround节点及connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rp);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.NotBehind, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), qoaBean.r2, lookaroundNode);
        // 2.3 替换原有节点
        TreeUtils.replaceChild(qoaBean.r2.father, qoaBean.r2, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(connectNode.father, connectNode, qoaBean.r2, tree);

        return result;
    }

    private static String repair25(QOABean qoaBean, Tree tree, Set<Integer> sigma_rp_minus_first_rq) {
        String result = "";
        // 1. 保存必要内容
        int r1_min = qoaBean.r1.cmin;
        int r1_max = qoaBean.r1.cmax;
        int r2_min = qoaBean.r2.cmin;
        int r2_max = qoaBean.r2.cmax;

        // 2. 修改
        // 2.1 修改rq的cmin和cmax
        qoaBean.r1.cmin = qoaBean.r1.cmin - 1;
        qoaBean.r1.cmax = qoaBean.r1.cmax - 1;
        qoaBean.r1.modified = true;
        // 2.2 新建CharsetNode
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rp_minus_first_rq, theta(sigma_rp_minus_first_rq));
        // 2.3 新建connectNode
        ConnectNode connectNode = new ConnectNode(tree.getCount(), charsetNode, qoaBean.r1);
        // 2.4 替换原有节点
        TreeUtils.replaceChild(qoaBean.r1.father, qoaBean.r1, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(connectNode.father, connectNode, qoaBean.r1, tree);
        qoaBean.r1.cmin = r1_min;
        qoaBean.r1.cmax = r1_max;
        qoaBean.r1.modified = false;

        return result;
    }

    private static String repair26(QOABean qoaBean, Tree tree, Set<Integer> sigma_rq_minus_first_rp) {
        String result = "";
        // 1. 保存必要内容
        int r1_min = qoaBean.r1.cmin;
        int r1_max = qoaBean.r1.cmax;
        int r2_min = qoaBean.r2.cmin;
        int r2_max = qoaBean.r2.cmax;

        // 2. 修改
        // 2.1 修改rq的cmin和cmax
        qoaBean.r2.cmin = qoaBean.r2.cmin - 1;
        qoaBean.r2.cmax = qoaBean.r2.cmax - 1;
        qoaBean.r2.modified = true;
        // 2.2 新建CharsetNode
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rq_minus_first_rp, theta(sigma_rq_minus_first_rp));
        // 2.3 新建connectNode
        ConnectNode connectNode = new ConnectNode(tree.getCount(), qoaBean.r2, charsetNode);
        // 2.4 替换原有节点
        TreeUtils.replaceChild(qoaBean.r2.father, qoaBean.r2, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(connectNode.father, connectNode, qoaBean.r2, tree);
        qoaBean.r2.cmin = r2_min;
        qoaBean.r2.cmax = r2_max;
        qoaBean.r2.modified = false;

        return result;
    }

    private static String repair27(QOABean qoaBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容

        // 2. 修改
        // 2.1 新建connect节点
        ConnectNode connectNode = new ConnectNode(tree.getCount(), qoaBean.r1, qoaBean.r2);
        // 2.2 新建BranchNode
        BranchNode branchNode = new BranchNode(tree.getCount());
        branchNode.addChild(connectNode);
        branchNode.addChild(qoaBean.outsideLoopNode.child);
        // 2.3 替换原有节点
        TreeUtils.replaceChild(qoaBean.outsideLoopNode.father, qoaBean.outsideLoopNode, branchNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(branchNode.father, branchNode, qoaBean.outsideLoopNode, tree);

        return result;
    }

    private static String repair28(QOABean qoaBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容

        // 2. 修改
        // 2.2 新建BranchNode
        BranchNode branchNode = new BranchNode(tree.getCount());
        branchNode.addChild(qoaBean.r2);
        branchNode.addChild(findRu_right(qoaBean.r2));
        // 2.3 替换原有节点
        TreeUtils.replaceChild(qoaBean.r2.father, qoaBean.r2, branchNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(branchNode.father, branchNode, qoaBean.r2, tree);

        return result;
    }

    private static String repair29(QOABean qoaBean, Tree tree) {
        String result = "";
        // 1. 保存必要内容

        // 2. 修改
        // 2.2 新建BranchNode
        BranchNode branchNode = new BranchNode(tree.getCount());
        branchNode.addChild(qoaBean.r2);
        branchNode.addChild(findRu_left(qoaBean.r2));
        // 2.3 替换原有节点
        TreeUtils.replaceChild(qoaBean.r2.father, qoaBean.r2, branchNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(branchNode.father, branchNode, qoaBean.r2, tree);

        return result;
    }

    private static Vector<SLQBean> SLQStaticAnalysis(Tree tree) {
        Vector<SLQBean> slqBeans = new Vector<>();

        Set<Integer> lookaroundNodesChildren = new HashSet<Integer>();
        for (LookaroundNode lookaroundNode : tree.lookaroundNodes.values()) {
            if (Thread.currentThread().isInterrupted()) return slqBeans;
            lookaroundNodesChildren.addAll(lookaroundNode.allChildrenNodeIds);
        }

        for (LoopNode loopNode : tree.loopNodes.values()) {
            if (Thread.currentThread().isInterrupted()) return slqBeans;
            if (lookaroundNodesChildren.contains(loopNode.id)) continue;

            SLQBean.slqType type = satisfySLQ1_or_3(loopNode, tree);
            if (type == SLQBean.slqType.SLQ1 && loopNode.cmax > 1) {
                slqBeans.add(new SLQBean(loopNode, SLQBean.slqType.SLQ1));
            } else if (type == SLQBean.slqType.SLQ2 && loopNode.cmax > 1) {
                slqBeans.add(new SLQBean(loopNode, SLQBean.slqType.SLQ2));
            }
            else if (!prefixIsNullable(tree.root, loopNode)) { // 这里的SLQ3包括了SLQ3、SLQ4、SLQ5，稍后在动态再做区分
                slqBeans.add(new SLQBean(loopNode, SLQBean.slqType.SLQ3));
            }
        }

        return slqBeans;
    }

    private static SLQBean.slqType satisfySLQ1_or_3(LoopNode loopNode, Tree tree) {
        SLQBean.slqType result = SLQBean.slqType.SLQ1;
        if (loopNode == tree.root) return result;
        TreeNode father = loopNode.father;
        TreeNode child = loopNode;
        assert father != null;
        while (father != tree.root) {
            if (Thread.currentThread().isInterrupted()) return result;
            if (father instanceof ConnectNode) {
                // 如果child来自右节点，判断左节点是否可空
                if (((ConnectNode)father).right == child) {
                    if (!((ConnectNode) father).left.nullable()) {
                        return null;
                    }
                    result = SLQBean.slqType.SLQ2;
                }
            }
            child = father;
            father = father.father;
            assert father != null;
        }
        if (father instanceof ConnectNode) {
            // 如果child来自右节点，判断左节点是否可空
            if (((ConnectNode)father).right == child) {
                if (!((ConnectNode) father).left.nullable()) {
                    return null;
                }
                result = SLQBean.slqType.SLQ2;
            }
        }
        child = father;
        father = father.father;
        assert father != null;
        return result;
    }

    private static SLQBean SLQDynamicAnalysis(Vector<SLQBean> slqBeans, Tree tree) {
        for (SLQBean slqBean : slqBeans) {
            if (Thread.currentThread().isInterrupted()) return null;
            if (slqBean.type == SLQBean.slqType.SLQ1 || slqBean.type == SLQBean.slqType.SLQ2) {
                Enumerator prefixEnumerator = new Enumerator(generatePrePath(tree.root, slqBean.r).getNormalizePath(false), tree.haveAdvancedFeatures);
                generatePaths(slqBean.r);
                for (Path path : slqBean.r.paths) {
                    if (Thread.currentThread().isInterrupted()) return null;
                    prefixEnumerator.reset();
                    Enumerator pumpEnumerator = new Enumerator(path.getNormalizePath(true), tree.haveAdvancedFeatures);
                    AttackBean attackBean = dynamicValidate(prefixEnumerator, pumpEnumerator, VulType.SLQ, tree);
                    if (attackBean != null) {
                        slqBean.attackBean = attackBean;
                        return slqBean;
                    }
                }
            }
            else { // 静态分析SLQ3包括了SLQ3、SLQ4、SLQ5
                Vector<Path> r1_paths = generateALLPrePath(tree.root, slqBean.r);
                if (r1_paths.size() != 0) generatePaths(slqBean.r, r1_paths.get(r1_paths.size() - 1).getPathSize());
                for (Path r1_path : r1_paths) {
                    if (Thread.currentThread().isInterrupted()) return null;
                    // 判断是否是SLQ3
                    for (Path r2_path : slqBean.r.paths) {
                        if (Thread.currentThread().isInterrupted()) return null;
                        if (r1_path.getPathSize() < r2_path.getPathSize()) break;
                        else if (r1_path.getPathSize() > r2_path.getPathSize()) continue;

                        Vector<Set<Integer>> r1_normalize_path = r1_path.getNormalizePath(false);
                        Vector<Set<Integer>> r2_normalize_path = r2_path.getNormalizePath(true);

                        if (r1_normalize_path.size() == 0 || r2_normalize_path.size() == 0) continue;

                        // 判断是否每一位都能相交
                        boolean canIntersect = true;
                        Vector<Set<Integer>> intersection = new Vector<>();
                        for (int i = 0; i < r1_normalize_path.size(); i++) {
                            if (Thread.currentThread().isInterrupted()) return null;
                            Set<Integer> tmp = new HashSet<>();
                            tmp.addAll(r1_normalize_path.get(i));
                            tmp.retainAll(r2_normalize_path.get(i));
                            if (tmp.size() == 0) {
                                canIntersect = false;
                                break;
                            }
                            intersection.add(tmp);
                        }

                        if (canIntersect) { // 说明是SLQ3
                            Enumerator prefixEnumerator = new Enumerator(new Vector<>(), tree.haveAdvancedFeatures);
                            Enumerator pumpEnumerator = new Enumerator(intersection, tree.haveAdvancedFeatures);
                            AttackBean attackBean = dynamicValidate(prefixEnumerator, pumpEnumerator, VulType.SLQ, tree);
                            if (attackBean != null) {
                                slqBean.attackBean = attackBean;
                                return slqBean;
                            }
                        }
                    }
                }


                // 若不是SLQ3，则判断是否是SLQ4或SLQ5
                // 挑出slqBean.r的子节点中所有的LoopNode
                Vector<LoopNode> loopNodes = new Vector<>();
                for (int child_id : slqBean.r.allChildrenNodeIds) {
                    if (Thread.currentThread().isInterrupted()) return null;
                    if (tree.loopNodes.keySet().contains(child_id)) {
                        loopNodes.add(tree.loopNodes.get(child_id));
                    }
                }

                // 对每一个LoopNode，判断是否是SLQ4或SLQ5
                for (LoopNode rq2 : loopNodes) {
                    if (Thread.currentThread().isInterrupted()) return null;
                    // 判断前缀是否不为空
                    if (prefixIsNullable(slqBean.r, rq2)) continue;

                    // 判断语言是否相交
                    if (r1_paths.size() > 0 && rq2.paths.get(rq2.paths.size() - 1).getPathSize() < r1_paths.get(r1_paths.size() - 1).getPathSize()) { // 如果路径长度小于r1的路径长度，扩大并重新生成路径
                        generatePaths(rq2, r1_paths.get(r1_paths.size() - 1).getPathSize());
                    }
                    for (Path rq2_path : rq2.paths) {
                        if (Thread.currentThread().isInterrupted()) return null;
                        for (Path r1_path : r1_paths) {
                            if (Thread.currentThread().isInterrupted()) return null;
                            if (r1_path.getPathSize() < rq2_path.getPathSize()) break;
                            else if (r1_path.getPathSize() > rq2_path.getPathSize()) continue;
                            Vector<Set<Integer>> rq2_normalize_path = rq2_path.getNormalizePath(true);
                            Vector<Set<Integer>> r1_normalize_path = r1_path.getNormalizePath(false);

                            // 判断是否每一位都能相交
                            boolean canIntersect = true;
                            Vector<Set<Integer>> intersection = new Vector<>();
                            for (int i = 0; i < rq2_normalize_path.size(); i++) {
                                if (Thread.currentThread().isInterrupted()) return null;
                                Set<Integer> tmp = new HashSet<>();
                                tmp.addAll(rq2_normalize_path.get(i));
                                tmp.retainAll(r1_normalize_path.get(i));
                                if (tmp.size() == 0) {
                                    canIntersect = false;
                                    break;
                                }
                                intersection.add(tmp);
                            }

                            if (canIntersect) { // 说明是SLQ4或SLQ5
                                Enumerator prefixEnumerator = new Enumerator(new Vector<>(), tree.haveAdvancedFeatures);
                                Vector<Set<Integer>> rq1 = generatePrePath(slqBean.r, rq2).getNormalizePath(false);
                                Vector<Set<Integer>> rq3 = generateSuffixPath(slqBean.r, rq2).getNormalizePath(false);
                                Vector<Set<Integer>> pumpPath = new Vector<>();
                                pumpPath.addAll(rq1);
                                pumpPath.addAll(intersection);
                                pumpPath.addAll(rq3);
                                Enumerator pumpEnumerator = new Enumerator(pumpPath, tree.haveAdvancedFeatures);
                                AttackBean attackBean = dynamicValidate(prefixEnumerator, pumpEnumerator, VulType.SLQ, tree);
                                if (attackBean != null) {
                                    slqBean.attackBean = attackBean;
                                    slqBean.setR_q2(rq2);
                                    if (suffixIsNullable(slqBean.r, rq2)) {
                                        slqBean.type = SLQBean.slqType.SLQ4;
                                    } else {
                                        slqBean.type = SLQBean.slqType.SLQ5;
                                    }
                                    return slqBean;
                                }
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    private static Vector<Pair<String, RepairType>> SLQRepair(SLQBean slqBean, Tree tree) {
        Vector<Pair<String, RepairType>> result = new Vector<>();
        if (slqBean.type == SLQBean.slqType.SLQ1 || slqBean.type == SLQBean.slqType.SLQ2) {
            // repair30
            if (tree.regex.charAt(0) != '^') {
                result.add(new Pair<>(repair30(slqBean, tree), RepairType.r30));
            }

            // repair31
            result.add(new Pair<>(repair31(slqBean, tree, 500), RepairType.r31));

            TreeNode r1 = findRu_left(slqBean.r);
            if (r1 != null && r1 == tree.root && r1 instanceof LoopNode && ((LoopNode) r1).cmin == 0) {
                result.add(new Pair<>(repair32(slqBean, tree, r1), RepairType.r32));
            }
        }
        else if (slqBean.type == SLQBean.slqType.SLQ3) {
            // repair30
            result.add(new Pair<>(repair30(slqBean, tree), RepairType.r30));

            // repair31
            result.add(new Pair<>(repair31(slqBean, tree, 500), RepairType.r31));

            // repair33
            result.add(new Pair<>(repair33(slqBean, tree), RepairType.r32));

            // repair34
            result.add(new Pair<>(repair34(slqBean, tree), RepairType.r34));

            // repair35
            Vector<TreeNode> preNodeList = TreeUtils.getPreNodeList(tree.root, slqBean.r);
            CharsetNode rp = scs(preNodeList, tree);
            if (rp != null) { // scs(rp)
                Set<Integer> sigma_rp = new HashSet<>();
                sigma_rp.addAll(rp.getCharset());
                Set<Integer> first_rq = new HashSet<>();
                first_rq.addAll(slqBean.r.getFirst());
                sigma_rp.removeAll(first_rq); // sigma_rp = sigma_rp \ first_rq
                if (sigma_rp.size() > 0) {
                    result.add(new Pair<>(repair35(slqBean, tree, rp, sigma_rp), RepairType.r35));
                }
            }

            // repair36
            Vector<TreeNode> tmpNodeList = new Vector<>();
            tmpNodeList.add(slqBean.r);
            CharsetNode rq = scs(tmpNodeList, tree);
            if (rq != null) { // scs(rq)
                Set<Integer> sigma_rq = new HashSet<>();
                sigma_rq.addAll(rq.getCharset());
                Set<Integer> first_rp = new HashSet<>();
                first_rp.addAll(tree.root.getFirst());
                sigma_rq.removeAll(first_rp); // sigma_rq = sigma_rq \ first_rp
                if (sigma_rq.size() > 0) {
                    result.add(new Pair<>(repair36(slqBean, tree, rq, sigma_rq), RepairType.r36));
                }
            }
        }
        else if (slqBean.type == SLQBean.slqType.SLQ4 || slqBean.type == SLQBean.slqType.SLQ5) {
            // repair30
            result.add(new Pair<>(repair30(slqBean, tree), RepairType.r30));

            // repair31
            result.add(new Pair<>(repair31(slqBean, tree, 500), RepairType.r31));

            // repair37
            result.add(new Pair<>(repair37(slqBean, tree), RepairType.r37));

            // repair38
            result.add(new Pair<>(repair38(slqBean, tree), RepairType.r38));

            // repair39
            Vector<TreeNode> preNodeList = TreeUtils.getPreNodeList(tree.root, slqBean.r);
            CharsetNode rp = scs(preNodeList, tree);
            if (rp != null) { // scs(rp)
                Set<Integer> sigma_rp = new HashSet<>();
                sigma_rp.addAll(rp.getCharset());
                Set<Integer> first_rt = new HashSet<>();
                first_rt.addAll(slqBean.r_q2.child.getFirst());
                sigma_rp.removeAll(first_rt); // sigma_rp = sigma_rp \ first_rt
                if (sigma_rp.size() > 0) {
                    result.add(new Pair<>(repair39(slqBean, tree, rp, sigma_rp), RepairType.r39));
                }
            }

            // repair40
            Vector<TreeNode> tmpNodeList = new Vector<>();
            tmpNodeList.add(slqBean.r_q2.child);
            CharsetNode rt = scs(tmpNodeList, tree);
            if (rt != null) { // scs(rt)
                Set<Integer> sigma_rt = new HashSet<>();
                sigma_rt.addAll(rt.getCharset());
                Set<Integer> first_rp = new HashSet<>();
                first_rp.addAll(tree.root.getFirst());
                sigma_rt.removeAll(first_rp); // sigma_rt = sigma_rt \ first_rp
                if (sigma_rt.size() > 0) {
                    result.add(new Pair<>(repair40(slqBean, tree, rt, sigma_rt), RepairType.r40));
                }
            }

        }
        return result;
    }

    private static String repair30(SLQBean slqBean, Tree tree) {
        String result = "";

        // 1. 保存必要内容
        TreeNode root = tree.root;

        // 2. 修改
        // 2.1 新建Begin节点和Connect节点
        PositionNode beginNode = new PositionNode(tree.getCount(), true);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), beginNode, root);
        // 2.2 替换树的root节点
        tree.root = connectNode;

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        tree.root = root;
        root.father = null;

        return result;
    }

    private static String repair31(SLQBean slqBean, Tree tree, int n_u) {
        String result = "";

        // 1. 保存必要内容
        int r_max = slqBean.r.cmax;

        // 2. 修改
        slqBean.r.cmax = n_u;
        slqBean.r.modified = true;

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        slqBean.r.cmax = r_max;
        slqBean.r.modified = false;

        return result;
    }

    private static String repair32(SLQBean slqBean, Tree tree, TreeNode r1_) {
        String result = "";
        // 1. 保存必要内容
        LoopNode r1 = (LoopNode) r1_;

        // 2. 修改
        // 2.1 修改r1的cmin
        r1.cmin = 1;
        // 2.1 新建Connect节点
        ConnectNode connectNode = new ConnectNode(tree.getCount(), r1, slqBean.r);
        // 2.2 新建Branch节点
        BranchNode branchNode = new BranchNode(tree.getCount());
        branchNode.addChild(slqBean.r);
        branchNode.addChild(connectNode);
        // 2.3 替换树的root节点
        tree.root = branchNode;

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        r1.cmin = 0;
        tree.root = r1;
        r1.father = null;

        return result;
    }

    private static String repair33(SLQBean slqBean, Tree tree) {
        String result = "";

        // 1. 保存必要内容
        TreeNode root = tree.root;

        // 2. 修改
        // 2.1 获取phi_rq
        setPhi(slqBean.r, true);
        generateRegex(slqBean.r);
        String phi_rq = slqBean.r.regex;
        setPhi(slqBean.r, false);
        // 2.2 新建lookaround节点和Connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rq);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), lookaroundNode, root);
        // 2.3 替换树的root节点
        tree.root = connectNode;

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        tree.root = root;
        root.father = null;

        return result;
    }

    private static String repair34(SLQBean slqBean, Tree tree) {
        String result = "";

        // 1. 保存必要内容
        TreeNode root = tree.root;
        TreeNode r_father = slqBean.r.father;

        // 2. 修改
        // 2.1 获取phi_rp
        String phi_rp = generatePreRegex(tree.root, slqBean.r);;
        // 2.2 新建lookaround节点和Connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rp);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), lookaroundNode, slqBean.r);
        // 2.3 替换节点
        TreeUtils.replaceChild(r_father, slqBean.r, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(r_father, connectNode, slqBean.r, tree);

        return result;
    }

    private static String repair35(SLQBean slqBean, Tree tree, CharsetNode rp, Set<Integer> sigma_rp_minus_first_rp) {
        String result = "";

        // 1. 保存必要内容
        TreeNode rp_father = rp.father;

        // 2. 修改
        // 2.1 新建CharsetNode节点
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rp_minus_first_rp, theta(sigma_rp_minus_first_rp));
        // 2.2 替换节点
        TreeUtils.replaceChild(rp_father, rp, charsetNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(rp_father, charsetNode, rp, tree);

        return result;
    }

    private static String repair36(SLQBean slqBean, Tree tree, CharsetNode rq, Set<Integer> sigma_rq_minus_first_rq) {
        String result = "";

        // 1. 保存必要内容
        TreeNode rq_father = rq.father;

        // 2. 修改
        // 2.1 新建CharsetNode节点
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rq_minus_first_rq, theta(sigma_rq_minus_first_rq));
        // 2.2 替换节点
        TreeUtils.replaceChild(rq_father, rq, charsetNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(rq_father, charsetNode, rq, tree);

        return result;
    }

    private static String repair37(SLQBean slqBean, Tree tree) {
        String result = "";

        // 1. 保存必要内容
        TreeNode root = tree.root;
        TreeNode r_father = slqBean.r.father;

        // 2. 修改
        // 2.1 获取phi_rt
        setPhi(slqBean.r_q2, true);
        generateRegex(slqBean.r_q2.child);
        String phi_rt = slqBean.r_q2.child.regex;
        setPhi(slqBean.r_q2, false);
        // 2.2 新建lookaround节点和Connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rt);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.NotBehind, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), root, lookaroundNode);
        // 2.3 替换树的root节点
        tree.root = connectNode;

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        tree.root = root;
        root.father = null;

        return result;
    }

    private static String repair38(SLQBean slqBean, Tree tree) {
        String result = "";

        // 1. 保存必要内容
        TreeNode root = tree.root;
        TreeNode r_father = slqBean.r.father;
        TreeNode r_t = slqBean.r_q2.child;
        TreeNode r_t_father = slqBean.r_q2;

        // 2. 修改
        // 2.1 获取phi_rp
        String phi_rp = generatePreRegex(tree.root, slqBean.r);
        // 2.2 新建lookaround节点和Connect节点
        SliceNode sliceNode = new SliceNode(tree.getCount(), phi_rp);
        LookaroundNode lookaroundNode = new LookaroundNode(tree.getCount(), LookaroundNode.LookaroundType.Neg, sliceNode);
        ConnectNode connectNode = new ConnectNode(tree.getCount(), lookaroundNode, r_t);
        // 2.3 替换节点
        TreeUtils.replaceChild(r_t_father, r_t, connectNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(r_t_father, connectNode, r_t, tree);

        return result;
    }

    private static String repair39(SLQBean slqBean, Tree tree, CharsetNode rp, Set<Integer> sigma_rp_minus_first_rt) {
        String result = "";

        // 1. 保存必要内容
        TreeNode rp_father = rp.father;

        // 2. 修改
        // 2.1 新建CharsetNode节点
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rp_minus_first_rt, theta(sigma_rp_minus_first_rt));
        // 2.2 替换节点
        TreeUtils.replaceChild(rp_father, rp, charsetNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(rp_father, charsetNode, rp, tree);

        return result;
    }

    private static String repair40(SLQBean slqBean, Tree tree, CharsetNode rt, Set<Integer> sigma_rt_minus_first_rp) {
        String result = "";

        // 1. 保存必要内容
        TreeNode rt_father = rt.father;

        // 2. 修改
        // 2.1 新建CharsetNode节点
        CharsetNode charsetNode = new CharsetNode(tree.getCount(), sigma_rt_minus_first_rp, theta(sigma_rt_minus_first_rp));
        // 2.2 替换节点
        TreeUtils.replaceChild(rt_father, rt, charsetNode, tree);

        // 3. 赋值
        result = tree.getRegex();

        // 4. 恢复
        TreeUtils.replaceChild(rt_father, charsetNode, rt, tree);

        return result;
    }

    /**
     * 路径的枚举类，用来从一条平凡路径中依次枚举出所有字符串
     */
    private static class Enumerator {
        Vector<Vector<Integer>> path; // 把Vector<Set<Integer>>转换成Vector<Vector<Integer>>存储
        Vector<Vector<Integer>> pathRand;
        Vector<Integer> indexs; // 路径中的每一位所遍历到的序号
        Random rand;
        int times; // 当前路径中已经遍历的次数
        boolean haveAdvancedFeatures; // 是否有高级特征

        public Enumerator(Vector<Set<Integer>> path, boolean haveAdvancedFeatures) {
            this.haveAdvancedFeatures = haveAdvancedFeatures;
            this.indexs = new Vector<>();
            this.path = new Vector<>();
            for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                this.path.add(new Vector<>(path.get(i)));
                this.indexs.add(0);
            }
            if (!haveAdvancedFeatures) {
                this.rand = new Random(System.currentTimeMillis());
                pathRand = new Vector<>();
                for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                    pathRand.add(new Vector<>(path.get(i)));
                }
            }
            this.times = 0;
        }

        public String next() {
            times++;
            if (haveAdvancedFeatures) return nextAdvanced();
            else return nextNoAdvanced();
        }

        private String nextAdvanced() {
            String sb = "";
            for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                int tmp = path.get(i).get(indexs.get(i));
                sb += (char) tmp;
            }

            for (int i = indexs.size() - 1; i >= 0 && !Thread.currentThread().isInterrupted(); i--) {
                // 如果这一位的index遍历到头，则重置这一位，进入下一轮循环让下一位进位
                if (indexs.get(i) == path.get(i).size()) {
                    indexs.set(i, 0);
                    continue;
                }
                else {
                    // 如果这一位的index还没有遍历到头，让这一位的index加1
                    indexs.set(i, indexs.get(i) + 1);
                    // 如果这一位经过加1遍历到头的话，重置这一位，给前一位加1
                    for (int j = i; j > 0 && indexs.get(j) == path.get(j).size() && !Thread.currentThread().isInterrupted(); j--) {
                        indexs.set(j - 1, indexs.get(j - 1) + 1);
                        indexs.set(j, 0);
                    }
                    break;
                }
            }
            return sb;
        }

        private String nextNoAdvanced() {
            // 随机给出path的组合
            String sb = "";
            for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                sb += getRandChar(i);
            }
            return sb;
        }

        private char getRandChar(int i) {
            if (pathRand.get(i).size() == 0) {
                pathRand.set(i, new Vector<>(path.get(i)));
            }
            int randIndex = rand.nextInt(pathRand.get(i).size());
            int randChar = pathRand.get(i).get(randIndex);
            pathRand.get(i).remove(randIndex);
            return (char) randChar;
        }

        public boolean hasNext() {
            // 如果paths中任何一位size为0，返回false
            for (int i = 0; i < path.size(); i++) {
                if (path.get(i).size() == 0) return false;
            }
            // if (haveAdvancedFeatures) {
            //     if (this.indexs.size() == 0) {
            //         return false;
            //     }
            //     int t1 = this.indexs.get(0);
            //     int t2 = this.path.get(0).size();
            //     boolean result = t1 < t2;
            //     return result;
            // }
            // else {
                return this.times < 1;
            // }
        }

        public boolean Empty() {
            return this.indexs.size() == 0;
        }

        public void reset() {
            this.times = 0;
            for (int i = 0; i < this.indexs.size() && !Thread.currentThread().isInterrupted(); i++) {
                this.indexs.set(i, 0);
            }
        }
    }

    /**
     * 对给定的前缀和中缀进行枚举并验证是否具有攻击性
     * @param preEnum 前缀枚举类
     * @param pumpEnum 中缀枚举类
     * @param type 检测的是OneCounting、POA、SLQ中哪类漏洞
     * @return 是否具有攻击性
     */
    private static AttackBean dynamicValidate(Enumerator preEnum, Enumerator pumpEnum, VulType type, Tree tree) {
        int pumpMaxLength = 50;
        if (type == VulType.OneCounting) {
            pumpMaxLength = 50;
        } else if (type == VulType.POA) {
            pumpMaxLength = 30000;
        } else if (type == VulType.SLQ) {
            pumpMaxLength = 30000;
        }

        // 如果前缀可空的话，前缀固定为""，只枚举后缀
        if (preEnum.Empty()) {
            while (pumpEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                String pump = pumpEnum.next();
                double matchingStepCnt = 0;
                if (debugStep) System.out.println("pump:" + pump);
                try {
                    if (type == VulType.SLQ)
                        matchingStepCnt = tree.testPattern4Search.getMatchingStepCnt("", pump, "\n\b\n", pumpMaxLength, 1000000);
                    else matchingStepCnt = tree.testPattern.getMatchingStepCnt("", pump, "\n\b\n", pumpMaxLength, 100000);
                } catch (StackOverflowError e) {
                    // e.printStackTrace();
                    System.out.println("StackOverflowError");
                    matchingStepCnt = 1000001;
                }
                if (debugStep) System.out.println(matchingStepCnt);
                if (matchingStepCnt > (type == VulType.SLQ ? 1e6 : 1e5)) {
                    return new AttackBean("", pump, "\n\b\n" , pumpMaxLength, true);
                }
                // System.out.println("");
            }
        }
        // 如果前缀不可空的话，前缀和中缀组合枚举
        else {
            while (preEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                String pre = preEnum.next();
                while (pumpEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                    String pump = pumpEnum.next();
                    double matchingStepCnt;
                    if (debugStep) System.out.println("pre:" + pre + "\npump:" + pump);
                    try {
                        if (type == VulType.SLQ) matchingStepCnt = tree.testPattern4Search.getMatchingStepCnt(pre, pump, "\n\b\n", pumpMaxLength, 1000000);
                        else matchingStepCnt = tree.testPattern.getMatchingStepCnt(pre, pump, "\n\b\n", pumpMaxLength, 100000);
                    } catch (StackOverflowError e) {
                        // e.printStackTrace();
                        System.out.println("StackOverflowError");
                        matchingStepCnt = 1000001;
                    }
                    if (debugStep) System.out.println(matchingStepCnt);
                    if (matchingStepCnt > (type == VulType.SLQ ? 1e6 : 1e5)) {
                        return new AttackBean(pre, pump, "\n\b\n", pumpMaxLength, true);
                    }
                }
            }
        }

        return null;
    }
}
