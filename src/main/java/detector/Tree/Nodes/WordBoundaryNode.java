package detector.Tree.Nodes;

import detector.Path.Path;
import detector.Path.PathNodeType;

public class WordBoundaryNode extends LeafNode {
    boolean type; // true为word boundary "\b"，false为non-word boundary "\B"
    public WordBoundaryNode(int id, int type, String selfRegex) {
        super(id, null);
        this.type = type == 3;
        this.selfRegex = selfRegex;
        this.len = 0;
    }

    @Override
    public boolean nullable() {
        return true;
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;
        if (type) {
            paths.add(new Path(PathNodeType.WordBoundaryLower));
        }
        else {
            paths.add(new Path(PathNodeType.WordBoundaryUpper));
        }
        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;
        if (type) {
            paths.add(new Path(PathNodeType.WordBoundaryLower));
        }
        else {
            paths.add(new Path(PathNodeType.WordBoundaryUpper));
        }
        pathsGenerated = true;
    }
    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;
        if (type) {
            shortestPath = new Path(PathNodeType.WordBoundaryLower);
        }
        else {
            shortestPath = new Path(PathNodeType.WordBoundaryUpper);
        }
        shortestPathGenerated = true;
    }
}
