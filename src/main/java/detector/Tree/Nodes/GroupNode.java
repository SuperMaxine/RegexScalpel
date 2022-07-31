package detector.Tree.Nodes;

public class GroupNode extends LinkNode{
    int localIndex;
    boolean isCaptured;
    public TreeNode child;
    public GroupNode(int id, int localIndex) {
        super(id, null);
        this.localIndex = localIndex;
    }

    public void setChild(TreeNode child) {
        this.child = child;
        child.setFather(this);
        addChildNodeId(child);
        this.len = child.len;
        this.first.addAll(child.first);
    }

    public void setIsCaptured(boolean isCaptured) {
        this.isCaptured = isCaptured;
    }

    @Override
    public void generateRegex() {
        this.regex = (this.isCaptured&&!phi ? "(" : "(?:") + child.regex + ")";
        if (marked) {
            this.regex = "▶▷" + this.regex + "◁◀";
        }
    }

    @Override
    public String getMermaidStruct() {
        String nodeName = getNodeName();
        return nodeName
                + "[\""
                + nodeName
                + "<br>id:" + this.id
                + "<br>" + (this.isCaptured ? "()" : "(?:)")
                + "<br>localIndex:" + this.localIndex
                + "\"]"
                + "\n";
    }

    @Override
    public boolean nullable() {
        return child.nullable();
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;
        this.paths = child.paths;
        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;
        this.paths = child.paths;
        pathsGenerated = true;
    }

    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;
        shortestPath = child.shortestPath;
        shortestPathGenerated = true;
    }

}
