package detector.Tree;

import detector.Analysis.ReDosBean.QODBean;
import detector.PreProcess;
import detector.Tree.Nodes.*;
import detector.Path.Path;
import redos.regex.Pattern4Search;
import redos.regex.redosPattern;
import regex.Pattern;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Vector;

import static detector.Tree.TreeUtils.setPhi;
import static regex.regexUtils.getCharSet;

public class Tree {
    public String regex;
    public redosPattern testPattern4Search;
    public Pattern4Search testPattern;
    public TreeNode root;
    private HashMap<Integer, Pattern.Node> groupNextNode; // 存放遇到groupTail后的下一个Pattern节点，以便继续建树。Key为localIndex，Value为下一个Pattern节点
    private HashMap<Integer, Integer> localIndex2groupIndex; // 存放localIndex和groupIndex的对应关系, 非捕获组的groupIndex为0

    private HashMap<Integer, GroupNode> localIndex2GroupNodes; // 存放捕获组（捕获组与非捕获组都记录）的信息，Key为localIndex，Value为GroupNode
    private HashMap<Integer, GroupNode> groupIndex2GroupNodes; // 存放捕获组（捕获组与非捕获组都记录）的信息，Key为groupIndex，Value为GroupNode

    private Vector<BackRefNode> backRefNodes; // 存放反向引用的信息，方便建树后setRefGroupNode

    public HashMap<Integer, LoopNode> loopNodes; // 存放循环节点, Key为节点id，Value为LoopNode

    public HashMap<Integer, BranchNode> branchNodes; // 存放分支节点, Key为节点id，Value为BranchNode

    public HashMap<Integer, LookaroundNode> lookaroundNodes; // 存放Lookaround节点, Key为节点id，Value为LookaroundNode

    private int count; // 建树的时候节点计数，用来做节点的id
    public boolean haveAdvancedFeatures = false;

    public int getCount() {
        return ++count;
    }

    private TreeNode buildTree(Pattern.Node root) {
        if (root == null) {
            return null;
        }

        TreeNode me = null;
        TreeNode brother = null;

        // 实际内容的节点
        if (root instanceof Pattern.CharProperty) {
            Pattern.CharProperty tmpRoot = (Pattern.CharProperty) root;
            me = new CharsetNode(getCount(), getCharSet(tmpRoot), tmpRoot.regex);
            brother = buildTree(root.next);
        }
        else if (root instanceof Pattern.SliceNode || root instanceof Pattern.BnM) {
            me = new SliceNode(getCount(), root);
            brother = buildTree(root.next);
        }

        // 捕获组 & 反向引用
        else if (root instanceof Pattern.GroupHead) {
            Pattern.GroupHead tmpRoot = (Pattern.GroupHead) root;
            me = new GroupNode(getCount(), tmpRoot.localIndex);
            localIndex2GroupNodes.put(tmpRoot.localIndex, (GroupNode) me);
            ((GroupNode) me).setChild(buildTree(root.next));
            brother = buildTree(groupNextNode.get(tmpRoot.localIndex));

        }
        else if (root instanceof Pattern.GroupTail) {
            Pattern.GroupTail tmpRoot = (Pattern.GroupTail) root;
            localIndex2groupIndex.put(tmpRoot.localIndex, tmpRoot.groupIndex);
            if (! (root.next instanceof Pattern.Loop)) {
                groupNextNode.put(tmpRoot.localIndex, root.next);
            }

            if (tmpRoot.groupIndex == 0) {
                localIndex2GroupNodes.get(tmpRoot.localIndex).setIsCaptured(false);
            }
            else {
                localIndex2GroupNodes.get(tmpRoot.localIndex).setIsCaptured(true);
                groupIndex2GroupNodes.put(tmpRoot.groupIndex, localIndex2GroupNodes.get(tmpRoot.localIndex));
            }
            return null;
        }
        else if (root instanceof Pattern.BackRef) {
            Pattern.BackRef tmpRoot = (Pattern.BackRef) root;
            me = new BackRefNode(getCount(), tmpRoot.groupIndex, tmpRoot.regex);
            // 为BackRefNode setRefGroupNode
            ((BackRefNode) me).setRefGroupNode(this.groupIndex2GroupNodes.get(((BackRefNode) me).groupIndex));
            backRefNodes.add((BackRefNode) me);
            haveAdvancedFeatures = true;
            brother = buildTree(root.next);
        }

        // 循环
        else if (root instanceof Pattern.GroupCurly) {
            Pattern.GroupCurly tmpRoot = (Pattern.GroupCurly) root;
            GroupNode groupNode = new GroupNode(getCount(), tmpRoot.localIndex);
            localIndex2GroupNodes.put(tmpRoot.localIndex, groupNode);
            groupNode.setChild(buildTree(tmpRoot.atom));
            localIndex2groupIndex.put(tmpRoot.localIndex, tmpRoot.groupIndex);
            groupNode.setIsCaptured(tmpRoot.groupIndex != 0);
            if (tmpRoot.groupIndex != 0) {
                groupIndex2GroupNodes.put(tmpRoot.groupIndex, groupNode);
            }
            me = new LoopNode(getCount(), tmpRoot.regex, tmpRoot.cmin, tmpRoot.cmax, groupNode, false);
            brother = buildTree(tmpRoot.next);

            loopNodes.put(me.id, (LoopNode) me);
        }
        else if (root instanceof Pattern.Curly) {
            Pattern.Curly tmpRoot = (Pattern.Curly) root;
            me = new LoopNode(getCount(), tmpRoot.regex, tmpRoot.cmin, tmpRoot.cmax, buildTree(tmpRoot.atom), false);
            brother = buildTree(tmpRoot.next);

            loopNodes.put(me.id, (LoopNode) me);
        }
        else if (root instanceof Pattern.Prolog) {
            Pattern.Prolog tmpRoot = (Pattern.Prolog) root;
            me = buildTree(tmpRoot.loop);
        }
        else if (root instanceof Pattern.Loop) {
            Pattern.Loop tmpRoot = (Pattern.Loop) root;
            me = new LoopNode(getCount(), tmpRoot.regex, tmpRoot.cmin, tmpRoot.cmax, buildTree(tmpRoot.body), false);
            brother = buildTree(tmpRoot.next);

            loopNodes.put(me.id, (LoopNode) me);
        }
        else if (root instanceof Pattern.Ques) {
            Pattern.Ques tmpRoot = (Pattern.Ques) root;
            me = new LoopNode(getCount(), tmpRoot.regex, 0, 1, buildTree(tmpRoot.atom), false);
            brother = buildTree(tmpRoot.next);

            loopNodes.put(me.id, (LoopNode) me);
        }

        // 分支
        else if (root instanceof Pattern.Branch) {
            Pattern.Branch tmpRoot = (Pattern.Branch) root;
            if (tmpRoot.getSize() == 1) {
                Pattern.Node child = tmpRoot.atoms[0] == null ? tmpRoot.atoms[1] : tmpRoot.atoms[0];
                me = new LoopNode(getCount(), tmpRoot.regex, 0, 1, buildTree(child), true);

                loopNodes.put(me.id, (LoopNode) me);
            }
            else {
                me = new BranchNode(getCount());

                branchNodes.put(me.id, (BranchNode) me);

                for (Pattern.Node node : tmpRoot.atoms) {
                    if (Thread.currentThread().isInterrupted()) return null;
                    if (node == null) {
                        continue;
                    }
                    ((BranchNode) me).addChild(buildTree(node));
                }

                if (((BranchNode) me).children.size() < tmpRoot.size) {
                    ((BranchNode) me).addChild(new CharsetNode(getCount(), new HashSet<>(), ""));
                }
            }
            brother = buildTree(tmpRoot.conn.next);
        }
        else if (root instanceof Pattern.BranchConn) {
            return null;
        }

        // lookaround
        else if (root instanceof Pattern.Pos){
            Pattern.Pos tmpRoot = (Pattern.Pos) root;
            TreeNode child = buildTree(tmpRoot.cond);
            assert child instanceof GroupNode;
            me = new LookaroundNode(getCount(), LookaroundNode.LookaroundType.Pos, ((GroupNode) child).child);

            lookaroundNodes.put(me.id, (LookaroundNode) me);
            haveAdvancedFeatures = true;

            brother = buildTree(tmpRoot.next);
        }
        else if (root instanceof Pattern.Neg) {
            Pattern.Neg tmpRoot = (Pattern.Neg) root;
            TreeNode child = buildTree(tmpRoot.cond);
            assert child instanceof GroupNode;
            me = new LookaroundNode(getCount(), LookaroundNode.LookaroundType.Neg, ((GroupNode) child).child);

            lookaroundNodes.put(me.id, (LookaroundNode) me);
            haveAdvancedFeatures = true;

            brother = buildTree(tmpRoot.next);
        }
        else if (root instanceof Pattern.Behind) {
            Pattern.Behind tmpRoot = (Pattern.Behind) root;
            TreeNode child = buildTree(tmpRoot.cond);
            assert child instanceof GroupNode;
            me = new LookaroundNode(getCount(), LookaroundNode.LookaroundType.Behind, ((GroupNode) child).child);

            lookaroundNodes.put(me.id, (LookaroundNode) me);
            haveAdvancedFeatures = true;

            brother = buildTree(tmpRoot.next);
        }
        else if (root instanceof Pattern.NotBehind) {
            Pattern.NotBehind tmpRoot = (Pattern.NotBehind) root;
            TreeNode child = buildTree(tmpRoot.cond);
            assert child instanceof GroupNode;
            me = new LookaroundNode(getCount(), LookaroundNode.LookaroundType.NotBehind, ((GroupNode) child).child);

            lookaroundNodes.put(me.id, (LookaroundNode) me);
            haveAdvancedFeatures = true;

            brother = buildTree(tmpRoot.next);
        }

        // "^"、"$"
        else if (root instanceof Pattern.Begin || root instanceof Pattern.Caret || root instanceof Pattern.UnixCaret) {
            me = new PositionNode(getCount(), true);
            haveAdvancedFeatures = true;
            brother = buildTree(root.next);
        }
        else if (root instanceof Pattern.Dollar || root instanceof Pattern.UnixDollar) {
            me = new PositionNode(getCount(), false);
            haveAdvancedFeatures = true;
            brother = buildTree(root.next);
        }

        // "\b"、"\B"
        else if (root instanceof Pattern.Bound) {
            Pattern.Bound tmpRoot = (Pattern.Bound) root;
            me = new WordBoundaryNode(getCount(), tmpRoot.type, tmpRoot.regex);
            haveAdvancedFeatures = true;
            brother = buildTree(root.next);
        }

        else {
            // throw new RuntimeException("Unsupported node type: " + root.getClass().getName());
            return buildTree(root.next);
        }

        if (brother != null) {
            return new ConnectNode(getCount(), me, brother);
        }
        else {
            return me;
        }
    }

    public static String generateRegex(TreeNode root) {
        String result = "";
        if (root == null) {
            return "";
        }
        else if (root instanceof LeafNode) {
            LeafNode tmpNode = (LeafNode) root;
            tmpNode.generateRegex();
        }
        else if (root instanceof LinkNode) {
            if (root instanceof LoopNode) {
                LoopNode tmpNode = (LoopNode) root;
                generateRegex(tmpNode.child);
                tmpNode.generateRegex();
            }
            else if (root instanceof ConnectNode) {
                ConnectNode tmpNode = (ConnectNode) root;
                generateRegex(tmpNode.left);
                generateRegex(tmpNode.right);
                tmpNode.generateRegex();
            }
            else if (root instanceof GroupNode) {
                GroupNode tmpNode = (GroupNode) root;
                generateRegex(tmpNode.child);
                tmpNode.generateRegex();
            }
            else if (root instanceof BranchNode) {
                BranchNode tmpNode = (BranchNode) root;
                for (TreeNode child : tmpNode.children) {
                    if (Thread.currentThread().isInterrupted()) return null;
                    generateRegex(child);
                }
                tmpNode.generateRegex();
            }
            else if (root instanceof LookaroundNode) {
                LookaroundNode tmpNode = (LookaroundNode) root;
                generateRegex(tmpNode.child);
                tmpNode.generateRegex();
            }
        }
        else {
            throw new RuntimeException("Unknown TreeNode type: " + root.getClass().getName());
        }

        result = root.regex;

        return result;
    }

    public static void generatePaths(TreeNode root) {
        if (root == null) {
            return;
        }
        else if (root instanceof LeafNode) {
            if (root instanceof BackRefNode) {
                generatePaths(((BackRefNode) root).refGroupNode);
            }
            LeafNode tmpNode = (LeafNode) root;
            // tmpNode.generatePaths(maxPathLength);
            tmpNode.generatePaths();
        }
        else if (root instanceof LinkNode) {
            if (root instanceof LoopNode) {
                LoopNode tmpNode = (LoopNode) root;
                generatePaths(tmpNode.child);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths();
            }
            else if (root instanceof ConnectNode) {
                ConnectNode tmpNode = (ConnectNode) root;
                generatePaths(tmpNode.left);
                generatePaths(tmpNode.right);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths();
            }
            else if (root instanceof GroupNode) {
                GroupNode tmpNode = (GroupNode) root;
                generatePaths(tmpNode.child);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths();
            }
            else if (root instanceof BranchNode) {
                BranchNode tmpNode = (BranchNode) root;
                for (TreeNode child : tmpNode.children) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    generatePaths(child);
                }
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths();
            }
            else if (root instanceof LookaroundNode) {
                LookaroundNode tmpNode = (LookaroundNode) root;
                generatePaths(tmpNode.child);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths();
            }
        }
        else {
            throw new RuntimeException("Unknown TreeNode type: " + root.getClass().getName());
        }
    }

    public static void generatePaths(TreeNode root, int maxPathLength) {
        if (root == null) {
            return;
        }
        else if (root instanceof LeafNode) {
            if (root instanceof BackRefNode) {
                generatePaths(((BackRefNode) root).refGroupNode, maxPathLength);
            }
            LeafNode tmpNode = (LeafNode) root;
            // tmpNode.generatePaths(maxPathLength);
            tmpNode.generatePaths(maxPathLength);
        }
        else if (root instanceof LinkNode) {
            if (root instanceof LoopNode) {
                LoopNode tmpNode = (LoopNode) root;
                generatePaths(tmpNode.child, maxPathLength);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths(maxPathLength);
            }
            else if (root instanceof ConnectNode) {
                ConnectNode tmpNode = (ConnectNode) root;
                generatePaths(tmpNode.left, maxPathLength);
                generatePaths(tmpNode.right, maxPathLength);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths(maxPathLength);
            }
            else if (root instanceof GroupNode) {
                GroupNode tmpNode = (GroupNode) root;
                generatePaths(tmpNode.child, maxPathLength);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths(maxPathLength);
            }
            else if (root instanceof BranchNode) {
                BranchNode tmpNode = (BranchNode) root;
                for (TreeNode child : tmpNode.children) {
                    if (Thread.currentThread().isInterrupted()) return;
                    generatePaths(child, maxPathLength);
                }
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths(maxPathLength);
            }
            else if (root instanceof LookaroundNode) {
                LookaroundNode tmpNode = (LookaroundNode) root;
                generatePaths(tmpNode.child, maxPathLength);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths(maxPathLength);
            }
        }
        else {
            throw new RuntimeException("Unknown TreeNode type: " + root.getClass().getName());
        }
    }

    public static void generatePathsQOD(TreeNode root, int maxPathLength, QODBean qodBean) {
        if (root == null) {
            return;
        }
        else if (root instanceof LeafNode) {
            if (root instanceof BackRefNode) {
                generatePathsQOD(((BackRefNode) root).refGroupNode, maxPathLength, qodBean);
            }
            LeafNode tmpNode = (LeafNode) root;
            // tmpNode.generatePaths(maxPathLength);
            tmpNode.generatePaths();
        }
        else if (root instanceof LinkNode) {
            if (root instanceof LoopNode) {
                LoopNode tmpNode = (LoopNode) root;
                generatePathsQOD(tmpNode.child, maxPathLength, qodBean);
                // tmpNode.generatePaths(maxPathLength);
                if (tmpNode.id == qodBean.outsideLoopNode.id) { // 使用QOD方法生成路径
                    tmpNode.generatePathsQOD();
                }
                else {
                    tmpNode.generatePaths();
                }
            }
            else if (root instanceof ConnectNode) {
                ConnectNode tmpNode = (ConnectNode) root;
                generatePathsQOD(tmpNode.left, maxPathLength, qodBean);
                generatePathsQOD(tmpNode.right, maxPathLength, qodBean);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths();
            }
            else if (root instanceof GroupNode) {
                GroupNode tmpNode = (GroupNode) root;
                generatePathsQOD(tmpNode.child, maxPathLength, qodBean);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths();
            }
            else if (root instanceof BranchNode) {
                BranchNode tmpNode = (BranchNode) root;
                for (TreeNode child : tmpNode.children) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    generatePathsQOD(child, maxPathLength, qodBean);
                }
                // tmpNode.generatePaths(maxPathLength);
                if (tmpNode.id == qodBean.insideBranchNode.id) { // 使用QOD方法生成路径
                    tmpNode.generatePathsQOD();
                }
                else {
                    tmpNode.generatePaths();
                }
            }
            else if (root instanceof LookaroundNode) {
                LookaroundNode tmpNode = (LookaroundNode) root;
                generatePathsQOD(tmpNode.child, maxPathLength, qodBean);
                // tmpNode.generatePaths(maxPathLength);
                tmpNode.generatePaths();
            }
        }
        else {
            throw new RuntimeException("Unknown TreeNode type: " + root.getClass().getName());
        }
    }


    public static void generateShortestPath(TreeNode root) {
        if (root == null) {
            return;
        }
        else if (root instanceof LeafNode) {
            if (root instanceof BackRefNode) {
                generateShortestPath(((BackRefNode) root).refGroupNode);
            }
            LeafNode tmpNode = (LeafNode) root;
            tmpNode.generateShortestPath();
        }
        else if (root instanceof LinkNode) {
            if (root instanceof LoopNode) {
                LoopNode tmpNode = (LoopNode) root;
                generateShortestPath(tmpNode.child);
                tmpNode.generateShortestPath();
            }
            else if (root instanceof ConnectNode) {
                ConnectNode tmpNode = (ConnectNode) root;
                generateShortestPath(tmpNode.left);
                generateShortestPath(tmpNode.right);
                tmpNode.generateShortestPath();
            }
            else if (root instanceof GroupNode) {
                GroupNode tmpNode = (GroupNode) root;
                generateShortestPath(tmpNode.child);
                tmpNode.generateShortestPath();
            }
            else if (root instanceof BranchNode) {
                BranchNode tmpNode = (BranchNode) root;
                for (TreeNode child : tmpNode.children) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    generateShortestPath(child);
                }
                tmpNode.generateShortestPath();
            }
            else if (root instanceof LookaroundNode) {
                LookaroundNode tmpNode = (LookaroundNode) root;
                generateShortestPath(tmpNode.child);
                tmpNode.generateShortestPath();
            }
        }
        else {
            throw new RuntimeException("Unknown TreeNode type: " + root.getClass().getName());
        }
    }

    public static Path generatePrePath(TreeNode root, TreeNode child) {
        Path result = new Path();
        if (root == child) return result;

        TreeNode father = child.father;
        assert father != null;
        while (father != root) {
            if (Thread.currentThread().isInterrupted()) return result;
            if (father instanceof ConnectNode) {
                // 如果child来自右节点，判断左节点是否可空
                if (((ConnectNode)father).right == child) {
                    generateShortestPath(((ConnectNode)father).left);
                    result = new Path(((ConnectNode)father).left.shortestPath, result);
                }
            }
            child = father;
            father = father.father;
            assert father != null;
        }
        if (father instanceof ConnectNode) {
            // 如果child来自右节点，判断左节点是否可空
            if (((ConnectNode)father).right == child) {
                generateShortestPath(((ConnectNode)father).left);
                result = new Path(((ConnectNode)father).left.shortestPath, result);
            }
        }
        return result;
    }

    public static Path generateSuffixPath(TreeNode root, TreeNode child) {
        Path result = new Path();
        if (root == child) return result;

        TreeNode father = child.father;
        assert father != null;
        while (father != root) {
            if (Thread.currentThread().isInterrupted()) return result;
            if (father instanceof ConnectNode) {
                // 如果child来自右节点，判断左节点是否可空
                if (((ConnectNode)father).left == child) {
                    generateShortestPath(((ConnectNode)father).right);
                    result = new Path(((ConnectNode)father).right.shortestPath, result);
                }
            }
            child = father;
            father = father.father;
            assert father != null;
        }
        if (father instanceof ConnectNode) {
            // 如果child来自右节点，判断左节点是否可空
            if (((ConnectNode)father).left == child) {
                generateShortestPath(((ConnectNode)father).right);
                result = new Path(((ConnectNode)father).right.shortestPath, result);
            }
        }
        return result;
    }

    public static Vector<Path> generateALLPrePath(TreeNode root, TreeNode child) {
        Vector<Path> result = new Vector<Path>();
        if (root == child) return result;

        TreeNode father = child.father;
        assert father != null;
        while (father != root) {
            if (Thread.currentThread().isInterrupted()) return result;
            if (father instanceof ConnectNode) {
                // 如果child来自右节点，判断左节点是否可空
                if (((ConnectNode)father).right == child) {
                    generatePaths(((ConnectNode)father).left);
                    if (result.size() == 0) result.addAll(((ConnectNode)father).left.paths);
                    else {
                        Vector<Path> tmp = new Vector<Path>();
                        for (Path p : ((ConnectNode)father).left.paths) {
                            if (Thread.currentThread().isInterrupted()) return result;
                            for (Path q : result) {
                                if (Thread.currentThread().isInterrupted()) return result;
                                tmp.add(new Path(p, q));
                            }
                        }
                        result = tmp;
                    }
                }
            }
            child = father;
            father = father.father;
            assert father != null;
        }
        if (father instanceof ConnectNode) {
            // 如果child来自右节点，判断左节点是否可空
            if (((ConnectNode)father).right == child) {
                generatePaths(((ConnectNode)father).left);
                if (result.size() == 0) result.addAll(((ConnectNode)father).left.paths);
                else {
                    Vector<Path> tmp = new Vector<Path>();
                    for (Path p : ((ConnectNode)father).left.paths) {
                        if (Thread.currentThread().isInterrupted()) return result;
                        for (Path q : result) {
                            if (Thread.currentThread().isInterrupted()) return result;
                            tmp.add(new Path(p, q));
                        }
                    }
                    result = tmp;
                }
            }
        }
        return result;
    }



    public static String generatePreRegex(TreeNode root, TreeNode child) {
        String result = "";
        if (root == child) return result;

        TreeNode father = child.father;
        assert father != null;
        while (father != root) {
            if (Thread.currentThread().isInterrupted()) return result;
            if (father instanceof ConnectNode) {
                if (((ConnectNode)father).right == child) {
                    setPhi(((ConnectNode)father).left, true);
                    generateRegex(((ConnectNode)father).left);
                    setPhi(((ConnectNode)father).left, false);
                    result = ((ConnectNode)father).left.regex + result;
                }
            }
            child = father;
            father = father.father;
            assert father != null;
        }
        if (father instanceof ConnectNode) {
            // 如果child来自右节点，判断左节点是否可空
            if (((ConnectNode)father).right == child) {
                setPhi(((ConnectNode)father).left, true);
                generateRegex(((ConnectNode)father).left);
                setPhi(((ConnectNode)father).left, false);
                result = ((ConnectNode)father).left.regex + result;
            }
        }
        return result;
    }

    public String getRegex() {
        generateRegex(this.root);
        return this.root.regex;
    }

    public Tree(String regex) {
        regex = PreProcess.preProcess(regex);
        this.regex = regex;
        testPattern = Pattern4Search.compile(regex);
        testPattern4Search = redosPattern.compile(regex);
        this.groupNextNode = new HashMap<>();
        this.localIndex2groupIndex = new HashMap<>();
        this.localIndex2GroupNodes = new HashMap<>();
        this.loopNodes = new HashMap<>();
        this.branchNodes = new HashMap<>();
        this.lookaroundNodes = new HashMap<>();
        this.count = 0;
        this.groupIndex2GroupNodes = new HashMap<>();
        this.backRefNodes = new Vector<>();


        this.root = buildTree(Pattern.compile(regex).root);

        // java不支持反向引用先于捕获组出现，所以改为在建树时setRefGroupNode
        // // 为BackRefNode setRefGroupNode
        // for (BackRefNode node : this.backRefNodes) {
        //     node.setRefGroupNode(this.groupIndex2GroupNodes.get(node.groupIndex));
        // }
    }
}
