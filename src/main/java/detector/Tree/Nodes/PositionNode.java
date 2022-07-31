package detector.Tree.Nodes;

public class PositionNode extends LeafNode {
    boolean position; // true为起始位置"^"，false为结束位置"$"
    public PositionNode(int id, boolean begin) {
        super(id, null);
        this.position = begin;
        this.selfRegex = begin ? "^" : "$";
        this.len = 0;
    }

    @Override
    public boolean nullable() {
        return true;
    }
}
