package detector.Tree.Nodes;

import detector.Path.Path;

import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

public class TreeNode {
    public int id;
    public TreeNode father = null;
    public String regex;
    public Vector<Path> paths;
    public Path shortestPath;
    boolean pathsGenerated = false;
    boolean shortestPathGenerated = false;
    public boolean marked = false;
    public boolean phi = false;
    public boolean modified = false;
    public int len = 0;
    public Set<Integer> first;
    TreeNode (int id, TreeNode father) {
        this.id = id;
        this.father = father;
        this.regex = "";
        this.paths = new Vector<Path>();
        this.first = new HashSet<>();
    }

    void setFather(TreeNode father) {
        this.father = father;
    }

    public String getMermaidStruct() {
        String nodeName = getNodeName();
        return nodeName
                + "[\""
                + nodeName
                + "<br>id:" + this.id
                + "\"]"
                + "\n";
    }

    public String getNodeName() {
        return this.toString().replace("detector.Tree.Nodes.", "").replace("@", "_");
    }

    public void generateRegex() {
        regex = "";
    }

    public boolean nullable() {
        return false;
    }

    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;
        pathsGenerated = true;
    }

    public void generatePaths() {
        if (pathsGenerated) return;
        pathsGenerated = true;
    }

    public void sortPaths(Vector<Path> paths){
        paths.sort(new Comparator<Path>() {
            @Override
            public int compare(Path o1, Path o2) {
                return o1.getPathSize() - o2.getPathSize();
            }
        });
    }

    public void generateShortestPath() {
        if (shortestPathGenerated) return;
        shortestPath = new Path();
        shortestPathGenerated = true;
    }

    public Set<Integer> getFirst() {
        // if (first == null) {
        //     first = new HashSet<>();
        //     if (this instanceof CharsetNode) {
        //         first.addAll(((CharsetNode) this).getCharset());
        //     }
        //     else if (this instanceof SliceNode) {
        //         first.add(((SliceNode) this).getSlice().get(0));
        //     }
        // }
        return first;
    }
}

