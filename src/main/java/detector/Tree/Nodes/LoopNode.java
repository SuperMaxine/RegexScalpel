package detector.Tree.Nodes;

import detector.Path.Path;

import java.util.Vector;

public class LoopNode extends LinkNode {
    public int cmin;
    public int cmax;
    public String selfRegex;
    public boolean fromBranch;
    public TreeNode child;
    public LoopNode(int id, String selfRegex, int cmin, int cmax, TreeNode child, boolean fromBranch) {
        super(id, null);
        this.cmin = cmin;
        this.cmax = cmax;
        this.fromBranch = fromBranch;
        this.selfRegex = selfRegex != "" ? selfRegex : guessQuantifier();
        this.child = child;
        this.first.addAll(child.first);
        child.setFather(this);
        addChildNodeId(child);

        if (cmin == cmax) {
            this.len = child.len;
        }
        else if (cmin < 2 && cmax == Integer.MAX_VALUE) {
            this.len = child.len * 2;
        }
        else if (cmin == 0 && cmax == 1) {
            this.len = child.len;
        }
        else {
            this.len = child.len * (cmin + 1);
        }
    }

    private String guessQuantifier() {
        if (fromBranch) {
            return "|";
        }
        else if (cmin == 0 && cmax == 1) {
            return "?";
        } else if (cmin == 0 && cmax == Integer.MAX_VALUE) {
            return "*";
        } else if (cmin == 1 && cmax == Integer.MAX_VALUE) {
            return "+";
        } else {
            return "{" + cmin + "," + cmax + "}";
        }
    }

    @Override
    public void generateRegex() {
        if (!modified) {
            this.regex = child.regex + this.selfRegex;
        }
        else {
            this.regex = child.regex + guessQuantifier();
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
                + "<br>" + this.selfRegex
                + "<br>cmin:" + this.cmin
                + "<br>cmax:" + this.cmax
                + "\"]"
                + "\n";
    }

    @Override
    public boolean nullable() {
        return child.nullable() || cmin == 0;
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;

        Vector<Path> minPaths = new Vector<>();
        Path emptyPath = new Path();
        minPaths.add(emptyPath);

        for (int i = 0; i < cmin; i++) {
            if (Thread.currentThread().isInterrupted()) return ;
            Vector<Path> new_minPaths = new Vector<>();
            for (Path path : child.paths) {
                if (Thread.currentThread().isInterrupted()) return ;
                for (Path minPath : minPaths) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    if (path.getPathSize() + minPath.getPathSize() > maxPathLength) continue;
                    Path newPath = new Path(minPath, path);
                    new_minPaths.add(newPath);
                }
            }
            minPaths = new_minPaths;
        }

        for (int i = cmin; i < cmax && i < maxPathLength; i++) {
            if (Thread.currentThread().isInterrupted()) return ;
            this.paths.addAll(minPaths);
            Vector<Path> new_Paths = new Vector<>();
            for (Path path : child.paths) {
                if (Thread.currentThread().isInterrupted()) return ;
                for (Path lastPath : minPaths) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    if (path.getPathSize() + lastPath.getPathSize() > maxPathLength) continue;
                    Path newPath = new Path(path, lastPath);
                    new_Paths.add(newPath);
                }
            }
            minPaths = new_Paths;
        }
        this.paths.addAll(minPaths);

        sortPaths(this.paths);
        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;



        Vector<Path> minPaths = new Vector<>();
        Path emptyPath = new Path();
        minPaths.add(emptyPath);

        for (int i = 0; i < cmin; i++) {
            if (Thread.currentThread().isInterrupted()) return ;
            Vector<Path> new_minPaths = new Vector<>();
            for (Path path : child.paths) {
                if (Thread.currentThread().isInterrupted()) return ;
                for (Path minPath : minPaths) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    if (path.getPathSize() + minPath.getPathSize() > this.len) continue;
                    Path newPath = new Path(minPath, path);
                    new_minPaths.add(newPath);
                }
            }
            minPaths = new_minPaths;
        }

        for (int i = cmin; i < cmax && i < this.len; i++) {
            if (Thread.currentThread().isInterrupted()) return ;
            this.paths.addAll(minPaths);
            Vector<Path> new_Paths = new Vector<>();
            for (Path path : child.paths) {
                if (Thread.currentThread().isInterrupted()) return ;
                for (Path lastPath : minPaths) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    if (path.getPathSize() + lastPath.getPathSize() > this.len) continue;
                    Path newPath = new Path(path, lastPath);
                    new_Paths.add(newPath);
                }
            }
            minPaths = new_Paths;
        }
        this.paths.addAll(minPaths);

        sortPaths(this.paths);
        pathsGenerated = true;
    }

    public void generatePathsQOD() {
        if (pathsGenerated) return;

        Vector<Path> minPaths = new Vector<>();
        Path emptyPath = new Path();
        minPaths.add(emptyPath);

        for (int i = 0; i < cmin; i++) {
            if (Thread.currentThread().isInterrupted()) return ;
            Vector<Path> new_minPaths = new Vector<>();
            for (Path path : child.paths) {
                if (Thread.currentThread().isInterrupted()) return ;
                // if (path.comeFrom == null) continue;
                for (Path minPath : minPaths) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    // if (minPath.comeFrom == null) continue;
                    if (path.getPathSize() + minPath.getPathSize() > this.len) continue;
                    Path newPath = new Path(minPath, path);
                    new_minPaths.add(newPath);
                }
            }
            minPaths = new_minPaths;
        }

        for (int i = cmin; i < cmax && i < this.len; i++) {
            if (Thread.currentThread().isInterrupted()) return ;
            this.paths.addAll(minPaths);
            Vector<Path> new_Paths = new Vector<>();
            for (Path path : child.paths) {
                if (Thread.currentThread().isInterrupted()) return ;
                for (Path lastPath : minPaths) {
                    if (Thread.currentThread().isInterrupted()) return ;
                    if (path.getPathSize() + lastPath.getPathSize() > this.len) continue;
                    Path newPath = new Path(path, lastPath);
                    new_Paths.add(newPath);
                }
            }
            minPaths = new_Paths;
        }
        this.paths.addAll(minPaths);

        sortPaths(this.paths);
        // pathsGenerated = true;
    }

    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;

        shortestPath = new Path();

        for (int i = 0; i < cmin; i++) {
            if (Thread.currentThread().isInterrupted()) return ;
            shortestPath = new Path(shortestPath, child.shortestPath);
        }

        shortestPathGenerated = true;
    }
}
