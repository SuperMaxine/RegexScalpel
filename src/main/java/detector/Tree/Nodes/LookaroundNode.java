package detector.Tree.Nodes;

import detector.Path.Path;
import detector.Path.PathNodeType;

public class LookaroundNode extends LinkNode {
    public enum LookaroundType {
        Pos,
        Neg,
        Behind,
        NotBehind
    }
    boolean direction; // lookaround的方向，true为正向(?=)(?!)，false为反向(?<=)(?<!)
    boolean positive; // lookaround的类型，true为positive(?=)(?<=)，false为negative(?!)(?<!)
    LookaroundType lookaroundType;
    public TreeNode child;
    public LookaroundNode(int id, LookaroundType type, TreeNode child) {
        super(id, null);
        this.lookaroundType = type;
        this.child = child;
        this.len = 0;
        child.setFather(this);
        addChildNodeId(child);
    }

    @Override
    public void generateRegex() {
        if (lookaroundType == LookaroundType.Pos) {
            this.regex = "(?=" + child.regex + ")";
        }
        else if (lookaroundType == LookaroundType.Neg) {
            this.regex = "(?!" + child.regex + ")";
        }
        else if (lookaroundType == LookaroundType.Behind) {
            this.regex = "(?<=" + child.regex + ")";
        }
        else if (lookaroundType == LookaroundType.NotBehind) {
            this.regex = "(?<!" + child.regex + ")";
        }
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
                + "<br>" + (lookaroundType == LookaroundType.Pos ? "?=" : lookaroundType == LookaroundType.Neg ? "?!" : lookaroundType == LookaroundType.Behind ? "?<=" : lookaroundType == LookaroundType.NotBehind ? "?<!" : "")
                + "\"]"
                + "\n";
    }

    @Override
    public boolean nullable() {
        return true;
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;

        PathNodeType type = null;
        switch (lookaroundType) {
            case Pos:
                type = PathNodeType.LookAroundPos;
                break;
            case Neg:
                type = PathNodeType.LookAroundNeg;
                break;
            case Behind:
                type = PathNodeType.LookAroundBehind;
                break;
            case NotBehind:
                type = PathNodeType.LookAroundNotBehind;
                break;
        }
        Path newPath = new Path(type, child.paths);
        paths.add(newPath);

        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;

        PathNodeType type = null;
        switch (lookaroundType) {
            case Pos:
                type = PathNodeType.LookAroundPos;
                break;
            case Neg:
                type = PathNodeType.LookAroundNeg;
                break;
            case Behind:
                type = PathNodeType.LookAroundBehind;
                break;
            case NotBehind:
                type = PathNodeType.LookAroundNotBehind;
                break;
        }
        Path newPath = new Path(type, child.paths);
        paths.add(newPath);

        pathsGenerated = true;
    }

    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;

        PathNodeType type = null;
        switch (lookaroundType) {
            case Pos:
                type = PathNodeType.LookAroundPos;
                break;
            case Neg:
                type = PathNodeType.LookAroundNeg;
                break;
            case Behind:
                type = PathNodeType.LookAroundBehind;
                break;
            case NotBehind:
                type = PathNodeType.LookAroundNotBehind;
                break;
        }
        Path newPath = new Path(type, child.paths);
        shortestPath = newPath;

        shortestPathGenerated = true;
    }
}
