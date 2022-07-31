package detector.Tree.Nodes;

import detector.Tree.Tree;
import detector.Path.Path;
import regex.Pattern;

import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

import static detector.Tree.TreeUtils.theta;

public class SliceNode extends ContentNode{
    Vector<Integer> slice;
    public SliceNode(int id, Pattern.Node actualNode) {
        super(id, null);
        slice = new Vector<Integer>();
        this.selfRegex = actualNode.regex;
        if (actualNode instanceof Pattern.SliceNode) {
            for (int i : ((Pattern.SliceNode) actualNode).buffer) {
                slice.add(i);
            }
        }
        else if (actualNode instanceof Pattern.BnM) {
            for (int i : ((Pattern.BnM) actualNode).buffer) {
                slice.add(i);
            }
        }

        if (this.selfRegex == "") {
            for (int i : slice) {
                this.selfRegex += String.valueOf((char) i);
            }
        }
        this.len = slice.size();

        first.add(slice.get(0));
    }

    public SliceNode(int id, String slice) { // 仅用于在结构中临时插入字符串
        super(id, null);
        this.slice = new Vector<Integer>();
        this.selfRegex = slice;
        this.len = slice.length();
        for (int i = 0; i < slice.length(); i++) {
            this.slice.add((int) slice.charAt(i));
        }
        first.add((int) slice.charAt(0));
    }

    @Override
    public boolean nullable() {
        return !(slice.size() > 0);
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;
        paths.add(new Path(slice));
        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;
        paths.add(new Path(slice));
        pathsGenerated = true;
    }

    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;
        shortestPath = new Path(slice);
        shortestPathGenerated = true;
    }

    public Vector<Integer> getSlice() {
        return slice;
    }

    public Vector<CharsetNode> scs(Tree tree) {
        Vector<CharsetNode> result = new Vector<CharsetNode>();
        if (slice.size() == 1) { // 按理说不可能出现slice为1的情况，出现这种情况会导致repair37出错
            throw new RuntimeException("slice.size() == 1");
            // Set<Integer> tmpSet = new HashSet<Integer>();
            // tmpSet.add(slice.get(0));
            // CharsetNode tmpCharsetNode = new CharsetNode(tree.getCount(), tmpSet, theta(tmpSet));
            // result.add(tmpCharsetNode);
        }
        else {
            for (int i = 0; i < slice.size(); i++) {
                Set<Integer> tmpSet = new HashSet<Integer>();
                tmpSet.add(slice.get(i));
                CharsetNode tmpCharsetNode = new CharsetNode(tree.getCount(), tmpSet, theta(tmpSet));
                result.add(tmpCharsetNode);
            }
        }
        return result;
    }
}
