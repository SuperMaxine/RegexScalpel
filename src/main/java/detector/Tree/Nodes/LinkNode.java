package detector.Tree.Nodes;

import java.util.HashSet;
import java.util.Set;

public class LinkNode extends TreeNode{
    public Set<Integer> allChildrenNodeIds; // 这个节点下所有的子节点(所有层)的id
    public LinkNode(int id, TreeNode father) {
        super(id, father);
        allChildrenNodeIds = new HashSet<>();
    }

    public void addChildNodeId(TreeNode child) {
        allChildrenNodeIds.add(child.id);
        if (child instanceof LinkNode) {
            allChildrenNodeIds.addAll(((LinkNode) child).allChildrenNodeIds);
        }
    }

    public void removeChildNodeId(TreeNode child) {
        allChildrenNodeIds.remove(child.id);
        if (child instanceof LinkNode) {
            allChildrenNodeIds.removeAll(((LinkNode) child).allChildrenNodeIds);
        }
    }
}
