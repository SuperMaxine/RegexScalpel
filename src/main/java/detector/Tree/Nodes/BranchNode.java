package detector.Tree.Nodes;

import detector.Path.Path;

import java.util.Vector;

public class BranchNode extends LinkNode{
    public Vector<TreeNode> children;
    public BranchNode(int id) {
        super(id, null);
        children = new Vector<TreeNode>();
    }

    @Override
    public void generateRegex() {
        String regex = "";
        regex += children.get(0).regex;
        for (int i = 1; i < children.size(); i++) {
            regex += "|";
            regex += children.get(i).regex;
        }
        this.regex = regex;
        if (marked) {
            this.regex = "▶▷" + this.regex + "◁◀";
        }
    }

    public void addChild(TreeNode child) {
        if (children != null) {
            children.add(child);
            child.setFather(this);
            addChildNodeId(child);
            if (child.len > this.len) {
                this.len = child.len;
            }
            this.first.addAll(child.first);
        }
    }

    @Override
    public boolean nullable() {
        for (TreeNode child : children) {
            if (child.nullable()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;
        for (TreeNode child : children) {
            this.paths.addAll(child.paths);
        }
        sortPaths(this.paths);
        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;
        for (TreeNode child : children) {
            this.paths.addAll(child.paths);
        }
        sortPaths(this.paths);
        pathsGenerated = true;
    }

    public void generatePathsQOD() {
        if (pathsGenerated) return;
        for (TreeNode child : children) {
            // this.paths.addAll(child.paths);
            int count = 0;
            for (Path path : child.paths) {
                Path tmpPath = new Path(path);
                // tmpPath.comeFrom = child.id;
                tmpPath.comeFrom = new Vector<>();
                tmpPath.comeFrom.add(child.id);
                this.paths.add(tmpPath);
                count++;
            }
        }
        sortPaths(this.paths);
        pathsGenerated = true;
    }

    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;
        Vector<Path> childShortestPaths = new Vector<Path>();
        for (TreeNode child : children) {
            childShortestPaths.add(child.shortestPath);
        }
        sortPaths(childShortestPaths);
        shortestPath = childShortestPaths.get(0);
        shortestPathGenerated = true;
    }

    public TreeNode getChildByID(int id) {
        for (TreeNode child : children) {
            if (child.id == id) {
                return child;
            }
        }
        return null;
    }

    public void removeChild(TreeNode child) {
        children.remove(child);
        removeChildNodeId(child);
    }
}
