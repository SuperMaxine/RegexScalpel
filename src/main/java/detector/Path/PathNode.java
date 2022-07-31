package detector.Path;

import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

public class PathNode {
    Set<Integer> charSet;
    PathNodeType type;
    Vector<Path> lookaroundPath;

    public PathNode(PathNode node) { // 深拷贝
        this.type = node.type;
        if (type == PathNodeType.CharSet) {
            this.charSet = new HashSet<>(node.charSet);
        }
        else if (type == PathNodeType.LookAroundPos || type == PathNodeType.LookAroundNeg || type == PathNodeType.LookAroundBehind || type == PathNodeType.LookAroundNotBehind) {
            this.lookaroundPath = new Vector<>();
            for (Path path : node.lookaroundPath) {
                this.lookaroundPath.add(new Path(path));
            }
        }
    }
    public PathNode(PathNodeType type, Vector<Path> lookaroundPath) {
        this.type = type;
        this.lookaroundPath = new Vector<Path>();
        this.lookaroundPath.addAll(lookaroundPath);
    }

    public PathNode(Set<Integer> charSet) {
        this.type = PathNodeType.CharSet;
        this.charSet = new HashSet<Integer>(charSet);
    }

    public PathNode(Integer i){
        this.type = PathNodeType.CharSet;
        this.charSet = new HashSet<Integer>();
        this.charSet.add(i);
    }

    public PathNode(PathNodeType type) {
        this.type = type;
    }

    public boolean isSet() {
        return type == PathNodeType.CharSet;
    }

    public boolean isLookAround() {
        return type == PathNodeType.LookAroundPos || type == PathNodeType.LookAroundNeg || type == PathNodeType.LookAroundBehind || type == PathNodeType.LookAroundNotBehind;
    }

    public boolean isBound() {
        return type == PathNodeType.WordBoundaryLower || type == PathNodeType.WordBoundaryUpper;
    }
}
