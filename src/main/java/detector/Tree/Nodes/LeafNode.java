package detector.Tree.Nodes;

public class LeafNode extends TreeNode {

    String selfRegex;
    public LeafNode(int id, TreeNode father) {
        super(id, father);
    }


    @Override
    public String getMermaidStruct() {
        String nodeName = getNodeName();
        return nodeName
                + "[\""
                + nodeName
                + "<br>id:" + this.id
                + "<br>" + this.selfRegex
                + "\"]"
                + "\n";
    }

    @Override
    public void generateRegex() {
        this.regex = this.selfRegex;
        if (marked) {
            this.regex = "▶▷" + this.regex + "◁◀";
        }
    }
}
