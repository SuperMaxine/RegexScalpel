package detector.Tree.Nodes;

public class BackRefNode extends LeafNode {
    public int groupIndex;
    public GroupNode refGroupNode;
    public BackRefNode(int id, Integer groupIndex, String selfRegex) {
        super(id, null);
        this.groupIndex = groupIndex;
        this.selfRegex = selfRegex;
    }

    public void setRefGroupNode(GroupNode refGroupNode) {
        this.refGroupNode = refGroupNode;
        this.len = refGroupNode.len;
        this.first.addAll(refGroupNode.first);
    }

    @Override
    public boolean nullable() {
        return refGroupNode.nullable();
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;
        paths = refGroupNode.paths;
        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;
        paths = refGroupNode.paths;
        pathsGenerated = true;
    }


    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;
        shortestPath = refGroupNode.shortestPath;
        shortestPathGenerated = true;
    }
}
