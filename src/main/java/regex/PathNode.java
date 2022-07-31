package regex;

import java.util.Vector;
import java.util.HashSet;
import java.util.Set;

public class PathNode {
    enum Type {
        set,
        lookaround,
        bound
    }
    enum boundType {
        lower,
        upper
    }
    // enum lookaroundType {
    //     Pos,
    //     Neg,
    //     Behind,
    //     NotBehind
    // }

    public Type type;
    public Set<Integer> charSet;
    public Vector<Path> lookaroundPath;
    private Analyzer.lookaroundType lookaroundType;
    public boundType bType;

    public PathNode(Set<Integer> charSet) {
        this.type = Type.set;
        this.charSet = charSet;
    }

    public PathNode(Vector<Path> lookaroundPath, Analyzer.lookaroundType lookaroundType) {
        this.type = Type.lookaround;
        this.lookaroundPath = lookaroundPath;
        this.lookaroundType = lookaroundType;
    }

    public PathNode(boundType bType) {
        this.type = Type.bound;
        this.bType = bType;
    }

    public PathNode(PathNode node) {
        this.type = node.type;

        if (node.charSet != null) this.charSet = new HashSet<>(node.charSet);
        else this.charSet = null;
        this.lookaroundPath = node.lookaroundPath;
        this.lookaroundType = node.lookaroundType;
        this.bType = node.bType;
    }

    public boolean isSet() {
        return type == Type.set;
    }

    public boolean isLookaround() {
        return type == Type.lookaround;
    }

    public boolean isBound() {
        return type == Type.bound;
    }

    public boundType getbType() {
        return bType;
    }

    public Analyzer.lookaroundType getLookaroundType() {
        return lookaroundType;
    }

    public Vector<Path> getLookaroundPath() {
        return lookaroundPath;
    }

    public Set<Integer> getCharSet() {
        return charSet;
    }

    public void setCharSet(Set<Integer> tmpSet) {
        this.charSet = tmpSet;
    }
}
