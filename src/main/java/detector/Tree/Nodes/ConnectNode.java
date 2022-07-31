package detector.Tree.Nodes;

import detector.Path.Path;

public class ConnectNode extends LinkNode {
    public TreeNode left;
    public TreeNode right;
    public ConnectNode(int id, TreeNode left, TreeNode right) {
        super(id, null);
        this.left = left;
        left.setFather(this);
        addChildNodeId(left);
        this.right = right;
        right.setFather(this);
        addChildNodeId(right);
        this.len = left.len + right.len;

        this.first.addAll(left.first);
        if (left.nullable()) {
            this.first.addAll(right.first);
        }
    }

    @Override
    public void generateRegex() {
        this.regex = left.regex + right.regex;
        if (marked) {
            this.regex = "▶▷" + this.regex + "◁◀";
        }
    }

    @Override
    public boolean nullable() {
        return left.nullable() && right.nullable();
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;
        for (Path leftPath : left.paths) {
            for (Path rightPath : right.paths) {
                if (leftPath.getPathSize() + rightPath.getPathSize() > maxPathLength) continue;
                Path path = new Path(leftPath, rightPath);
                this.paths.add(path);
            }
        }
        sortPaths(this.paths);
        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;
        for (Path leftPath : left.paths) {
            for (Path rightPath : right.paths) {
                if (leftPath.getPathSize() + rightPath.getPathSize() > this.len) continue;
                Path path = new Path(leftPath, rightPath);
                this.paths.add(path);
            }
        }
        sortPaths(this.paths);
        pathsGenerated = true;
    }

    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;
        shortestPath = new Path(left.shortestPath, right.shortestPath);
        shortestPathGenerated = true;
    }
}
