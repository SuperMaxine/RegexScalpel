package detector.Tree;

import detector.Analysis.ReDosBean.NQBean;
import detector.Analysis.ReDosBean.QOABean;
import detector.Analysis.ReDosBean.QODBean;
import detector.Analysis.ReDosBean.SLQBean;
import detector.Tree.Nodes.*;

import java.util.Collections;
import java.util.Set;
import java.util.Vector;

public class TreeUtils {
    public static void replaceChild(TreeNode father, TreeNode child, TreeNode newChild, Tree tree) {
        if (father == null) {
            // 说明原本的child就是root节点
            tree.root = newChild;
        }
        else {
            assert father instanceof LinkNode;
            if (father instanceof LoopNode) {
                ((LoopNode) father).child = newChild;
            }
            else if (father instanceof GroupNode) {
                ((GroupNode) father).child = newChild;
            }
            else if (father instanceof ConnectNode) {
                if (child == ((ConnectNode) father).left) {
                    ((ConnectNode) father).left = newChild;
                }
                else {
                    ((ConnectNode) father).right = newChild;
                }
            }
            else if (father instanceof BranchNode) {
                for (int i = 0; i < ((BranchNode) father).children.size(); i++) {
                    if (((BranchNode) father).children.get(i) == child) {
                        ((BranchNode) father).children.set(i, newChild);
                        break;
                    }
                }
            }
            else if (father instanceof LookaroundNode) {
                ((LookaroundNode) father).child = newChild;
            }
            else {
                throw new RuntimeException("Unknown father type");
            }
        }
        newChild.father = father;
    }

    public static void addMark(NQBean nqBean) {
        nqBean.insideLoopNode.marked = true;
        nqBean.outsideLoopNode.marked = true;
    }

    public static void addMark(QODBean qodBean) {
        qodBean.insideBranchNode.marked = true;
        qodBean.outsideLoopNode.marked = true;
    }

    public static void addMark(QOABean qoaBean) {
        if (qoaBean.outsideLoopNode != null) qoaBean.outsideLoopNode.marked = true;
        qoaBean.r1.marked = true;
        qoaBean.r2.marked = true;
    }

    public static void addMark(SLQBean slqBean) {
        slqBean.r.marked = true;
    }

    public static void removeMark(NQBean nqBean) {
        nqBean.insideLoopNode.marked = false;
        nqBean.outsideLoopNode.marked = false;
    }

    public static void removeMark(QODBean qodBean) {
        qodBean.insideBranchNode.marked = false;
        qodBean.outsideLoopNode.marked = false;
    }

    public static void removeMark(QOABean qoaBean) {
        if (qoaBean.outsideLoopNode != null) qoaBean.outsideLoopNode.marked = false;
        qoaBean.r1.marked = false;
        qoaBean.r2.marked = false;
    }

    public static void removeMark(SLQBean slqBean) {
        slqBean.r.marked = false;
    }

    public static boolean prefixIsNullable(TreeNode root, TreeNode child) { // 判断child(子正则)在root(父正则)中，是否可以作为开头(前缀是否可以为空)
        TreeNode father = child.father;
        assert father != null;
        while (father != root) {
            if (father instanceof ConnectNode) {
                // 如果child来自右节点，判断左节点是否可空
                if (((ConnectNode)father).right == child) {
                    if (!((ConnectNode) father).left.nullable()) {
                        return false;
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
                if (!((ConnectNode) father).left.nullable()) {
                    return false;
                }
            }
        }
        child = father;
        father = father.father;
        assert father != null;
        return true;
    }

    public static boolean suffixIsNullable(TreeNode root, TreeNode child) { // 判断child(子正则)在root(父正则)中，是否可以作为结尾(后缀是否可以为空)
        TreeNode father = child.father;
        assert father != null;
        while (father != root) {
            if (father instanceof ConnectNode) {
                // 如果child来自左节点，判断右节点是否可空
                if (((ConnectNode)father).left == child) {
                    if (!((ConnectNode) father).right.nullable()) {
                        return false;
                    }
                }
            }
            child = father;
            father = father.father;
            assert father != null;
        }
        return true;
    }

    public static boolean midfixIsNullable(TreeNode node1, TreeNode node2) {
        // TODO: 验证node1始终在node2左侧
        // 从node1开始，向右遍历树，直到遇到node2为止，判断是否可空
        TreeNode father = node1.father;
        assert father != null;
        while (father != null) {
            if (father instanceof LookaroundNode) {
                return false;
            }
            else if (father instanceof BranchNode && isChild(father, node2)) {
                return false;
            }
            else if (father instanceof ConnectNode) {
                if (((ConnectNode) father).left == node1 && isChild(((ConnectNode) father).right, node2)) {
                    return prefixIsNullable(((ConnectNode) father).right, node2);
                }
            }
            node1 = father;
            father = father.father;
            assert father != null;
        }
        return false;
    }

    public static LinkNode getCommonFather(TreeNode node1, TreeNode node2) {
        LinkNode father = (LinkNode) node1.father;
        assert father != null;
        while (father != null) {
            if (isChild(father, node2)) {
                return father;
            }
            father = (LinkNode) father.father;
            assert father != null;
        }
        return null;
    }

    public static LoopNode getNearestAncestorLoopNode(TreeNode node) {
        TreeNode father = node.father;
        while (father != null) {
            if (father instanceof LoopNode) {
                return (LoopNode) father;
            }
            father = father.father;
            assert father != null;
        }
        return null;
    }

    public static boolean node1IsLeftOfNode2(TreeNode node1, TreeNode node2, ConnectNode commonFather) {
        assert commonFather != null;
        if ((isChild(commonFather.left, node1) || node1.id == commonFather.left.id) && (isChild(commonFather.right, node2) || node2.id == commonFather.right.id)) {
            return true;
        }
        return false;
    }

    public static String getNodeMermaidTree(Tree tree) {
        String result = "graph TD\n";
        result += printTreeStruct(tree.root);
        result += "\nShow in Mermaid, visit: https://mermaid.live/\n";
        return result;
    }

    public static String printTreeStruct(TreeNode root) {
        String result = "";
        if (root == null) {
            result = "";
        }
        else if (root instanceof LeafNode) {
            LeafNode tmpNode = (LeafNode) root;
            result = tmpNode.getMermaidStruct();
        }
        else if (root instanceof LinkNode) {
            if (root instanceof LoopNode) {
                LoopNode tmpNode = (LoopNode) root;
                result = tmpNode.getMermaidStruct();
                result += tmpNode.getNodeName() + "-->" + tmpNode.child.getNodeName() + "\n";
                result += printTreeStruct(tmpNode.child);
            }
            else if (root instanceof ConnectNode) {
                ConnectNode tmpNode = (ConnectNode) root;
                result = tmpNode.getMermaidStruct();
                result += tmpNode.getNodeName() + "--left-->" + tmpNode.left.getNodeName() + "\n";
                result += tmpNode.getNodeName() + "--right-->" + tmpNode.right.getNodeName() + "\n";
                result += printTreeStruct(tmpNode.left);
                result += printTreeStruct(tmpNode.right);
            }
            else if (root instanceof GroupNode) {
                GroupNode tmpNode = (GroupNode) root;
                result = tmpNode.getMermaidStruct();
                result += tmpNode.getNodeName() + "-->" + tmpNode.child.getNodeName() + "\n";
                result += printTreeStruct(tmpNode.child);
            }
            else if (root instanceof BranchNode) {
                BranchNode tmpNode = (BranchNode) root;
                result = tmpNode.getMermaidStruct();
                for (TreeNode child : tmpNode.children) {
                    result += tmpNode.getNodeName() + "-->" + child.getNodeName() + "\n";
                    result += printTreeStruct(child);
                }
            }
            else if (root instanceof LookaroundNode) {
                LookaroundNode tmpNode = (LookaroundNode) root;
                result = tmpNode.getMermaidStruct();
                result += tmpNode.getNodeName() + "-->" + tmpNode.child.getNodeName() + "\n";
                result += printTreeStruct(tmpNode.child);
            }
        }
        else {
            throw new RuntimeException("Unknown TreeNode type: " + root.getClass().getName());
        }
        return result;
    }


    public static void setPhi(TreeNode root, boolean phi) {
        if (root == null) {
            return;
        }
        else if (root instanceof LeafNode) {
            LeafNode tmpNode = (LeafNode) root;
            tmpNode.phi = phi;
        }
        else if (root instanceof LinkNode) {
            if (root instanceof LoopNode) {
                LoopNode tmpNode = (LoopNode) root;
                tmpNode.phi = phi;
                setPhi(tmpNode.child, phi);
            }
            else if (root instanceof ConnectNode) {
                ConnectNode tmpNode = (ConnectNode) root;
                tmpNode.phi = phi;
                setPhi(tmpNode.left, phi);
                setPhi(tmpNode.right, phi);
            }
            else if (root instanceof GroupNode) {
                GroupNode tmpNode = (GroupNode) root;
                tmpNode.phi = phi;
                setPhi(tmpNode.child, phi);
            }
            else if (root instanceof BranchNode) {
                BranchNode tmpNode = (BranchNode) root;
                tmpNode.phi = phi;
                for (TreeNode child : tmpNode.children) {
                    setPhi(child, phi);
                }
            }
            else if (root instanceof LookaroundNode) {
                LookaroundNode tmpNode = (LookaroundNode) root;
                tmpNode.phi = phi;
                setPhi(tmpNode.child, phi);
            }
        }
        else {
            throw new RuntimeException("Unknown TreeNode type: " + root.getClass().getName());
        }
    }

    public static String theta_long (Set<Integer> set) {
        // TODO:转成\u0000-\uFFFF的形式
        String result = "[";
        for (Integer i : set) {
            result += int2String(i);
        }
        result += "]";
        return result;
    }

    private static String int2String(int i) {
        return int2String(i, false);
    }

    private static String int2String(int i, boolean mermaid) {

        switch (i) {
            case 7:
                return "\\a";
            case 8:
                return "\\b";
            case 9:
                return "\\t";
            case 10:
                return mermaid ? "\\n" : "\\n";
            case 11:
                return "\\v";
            case 12:
                return "\\f";
            case 13:
                return "\\r";
            case 92:
                return "\\\\";
            case 39:
                return "\\'";
            case 34:
                return mermaid ? "''" : "\\\"";
            case 40:
                return "\\(";
            case 123:
                return "\\{";
            case 91:
                return "\\[";
            case 46:
                return "\\.";
            case 124:
                return "\\|";
            case 42:
                return "\\*";
            case 63:
                return "\\?";
            case 43:
                return "\\+";
            default:
                return (char) i + "";
        }
    }

    public static String theta (Set<Integer> set) {
        // Convert set to Vector and sort it
        Vector<Integer> vector = new Vector<>(set);
        Collections.sort(vector);

        String result = "[";
        int last = -100;
        for (int i = 0; i < vector.size(); i++) {
            int cur = vector.get(i);
            if (last == -100) {
                result += int2Unicode(cur);
            }
            else if (cur != last + 1) {
                result += "-" + int2Unicode(last);
                result += int2Unicode(cur);
            }
            last = cur;
        }
        // if last char of result is "-"
        // if (result.charAt(result.length() - 1) == '-') {
        //     result += int2Unicode(vector.get(vector.size() - 1));
        // }

        result += "-"+int2Unicode(vector.get(vector.size() - 1));
        result += "]";
        return result;
    }

    public static String int2Unicode(int i) {
        String hex = Integer.toHexString(i);
        String result = "\\u";
        int len = hex.length();
        switch (hex.length()) {
            case 1:
                result += "000";
                break;
            case 2:
                result += "00";
                break;
            case 3:
                result += "0";
                break;
            case 4:
                result += "";
                break;
            default:
                throw new RuntimeException("Unsupported unicode: " + i);
        }
        result += hex;
        return result;
    }

    public static boolean isChild(TreeNode ancestor, TreeNode child) {
        if (ancestor instanceof LinkNode && ((LinkNode)ancestor).allChildrenNodeIds.contains(child.id)) {
            return true;
        }
        return false;
    }

    public static CharsetNode scs(Vector<TreeNode> nodeList, Tree tree) {
        Vector<CharsetNode> nodeCount = new Vector<>();
        for (TreeNode node : nodeList) {
            nodeCount.addAll(scsDG(node, tree));
            if (nodeCount.size() > 1) {
                break;
            }
        }
        if (nodeCount.size() == 1) {
            return nodeCount.get(0);
        }
        else {
            return null;
        }
    }

    public static Vector<CharsetNode> scsDG(TreeNode node, Tree tree) {
        Vector<CharsetNode> nodeCount = new Vector<>();
        if (node instanceof LeafNode) {
            if (node instanceof CharsetNode) {
                nodeCount.add((CharsetNode) node);
            }
            else if (node instanceof SliceNode) {
                nodeCount.addAll(((SliceNode) node).scs(tree));
            }
        }
        else if (node instanceof LinkNode) {
            if (node instanceof BranchNode) {
                for (TreeNode child : ((BranchNode) node).children) {
                    Vector<CharsetNode> tmp = scsDG(child, tree);
                    if (tmp.size() == 1) return tmp;
                    else if (tmp.size() > nodeCount.size()) nodeCount = tmp;
                }
            }
            else if (node instanceof ConnectNode) {
                nodeCount.addAll(scsDG(((ConnectNode) node).left, tree));
                if (nodeCount.size() > 1) return nodeCount;
                nodeCount.addAll(scsDG(((ConnectNode) node).right, tree));
            }
            else if (node instanceof LoopNode) {
                nodeCount.addAll(scsDG(((LoopNode) node).child, tree));
            }
            else if (node instanceof GroupNode) {
                nodeCount.addAll(scsDG(((GroupNode) node).child, tree));
            }
        }
        return nodeCount;
    }

    public static Vector<TreeNode> getPreNodeList(TreeNode root, TreeNode child) {
        Vector<TreeNode> result = new Vector<>();
        TreeNode father = child.father;
        assert father != null;
        while (father != root) {
            if (father instanceof ConnectNode) {
                // 如果child来自右节点，判断左节点是否可空
                if (((ConnectNode)father).right == child) {
                    result.add(((ConnectNode) father).left);
                }
            }
            child = father;
            father = father.father;
            assert father != null;
        }
        if (father instanceof ConnectNode) {
            // 如果child来自右节点，判断左节点是否可空
            if (((ConnectNode)father).right == child) {
                result.add(((ConnectNode) father).left);
            }
        }
        return result;
    }
}
