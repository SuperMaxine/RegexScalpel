package detector.Tree.Nodes;

import detector.Path.Path;

import java.util.Set;

public class CharsetNode extends ContentNode{
    Set<Integer> charset;
    public CharsetNode(int id, Set<Integer> charset, String regex) {
        super(id, null);
        this.charset = charset;
        this.first.addAll(charset);
        this.selfRegex = regex;
        this.len = 1;

        if (selfRegex == "" && charset.size() == 1) {
            selfRegex = String.valueOf((char) ((int) charset.iterator().next()));
        }
    }

    @Override
    public boolean nullable() {
        return charset.size() == 0;
    }

    @Override
    public void generatePaths(int maxPathLength) {
        if (pathsGenerated) return;
        paths.add(new Path(charset));
        pathsGenerated = true;
    }

    @Override
    public void generatePaths() {
        if (pathsGenerated) return;
        paths.add(new Path(charset));
        pathsGenerated = true;
    }


    @Override
    public void generateShortestPath() {
        if (shortestPathGenerated) return;
        shortestPath = new Path(charset);
        shortestPathGenerated = true;
    }

    public Set<Integer> getCharset() {
        return charset;
    }
}
