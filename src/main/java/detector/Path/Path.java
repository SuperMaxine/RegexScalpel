package detector.Path;


import regex.regexUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

public class Path {
    Vector<PathNode> path;
    Vector<Set<Integer>> normalizePath;
    int realLength = -1;
    boolean isNormalized = false;

    public Vector<Integer> comeFrom = null; // 用来记录来自于从哪个节点生成，仅用于QOD方法

    public Path() {
        path = new Vector<PathNode>();
        normalizePath = new Vector<Set<Integer>>();
    }

    public Path(Path leftPath, Path rightPath) {
        path = new Vector<PathNode>();
        normalizePath = new Vector<Set<Integer>>();
        path.addAll(leftPath.path);
        path.addAll(rightPath.path);
        if (leftPath.comeFrom != null && rightPath.comeFrom != null) { // 只有两个path都有comeFrom才能记录新的comeFrom，用于QOD方法，comeFrom为空时夹杂了非insideBranchNode节点，直接跳过
            comeFrom = new Vector<Integer>();
            comeFrom.addAll(leftPath.comeFrom);
            comeFrom.addAll(rightPath.comeFrom);
        }
        else if (leftPath.comeFrom != null && rightPath.getPathSize() == 0) {
            comeFrom = new Vector<Integer>();
            comeFrom.addAll(leftPath.comeFrom);
        }
        else if (rightPath.comeFrom != null && leftPath.getPathSize() == 0) {
            comeFrom = new Vector<Integer>();
            comeFrom.addAll(rightPath.comeFrom);
        }
    }

    public Path(PathNodeType type, Vector<Path> lookaroundPath) {
        path = new Vector<PathNode>();
        normalizePath = new Vector<Set<Integer>>();
        path.add(new PathNode(type, lookaroundPath));
    }

    public Path(Set<Integer> charSet) {
        path = new Vector<PathNode>();
        normalizePath = new Vector<Set<Integer>>();
        path.add(new PathNode(charSet));
    }

    public Path(Vector<Integer> slice) {
        path = new Vector<PathNode>();
        normalizePath = new Vector<Set<Integer>>();
        for (int i = 0; i < slice.size(); i++) {
            path.add(new PathNode(slice.get(i)));
        }
    }

    public Path(PathNodeType type) {
        path = new Vector<PathNode>();
        normalizePath = new Vector<Set<Integer>>();
        path.add(new PathNode(type));
    }

    public Path(Path path) { // 深拷贝
        this.path = new Vector<PathNode>();
        this.normalizePath = new Vector<Set<Integer>>();
        for (PathNode node : path.path) {
            this.path.add(new PathNode(node));
        }
        for (Set<Integer> set : path.normalizePath) {
            this.normalizePath.add(new HashSet<Integer>(set));
        }
    }

    public int getPathSize() {
        if (realLength == -1) {
            int count = 0;
            for (PathNode node : path) {
                if (node.type == PathNodeType.CharSet) {
                    count += 1;
                }
            }
            return count;
        }
        else {
            return realLength;
        }
    }

    public PathNode getFirstContentNode() {
        for (PathNode node : path) {
            if (node.type == PathNodeType.CharSet) {
                return node;
            }
        }
        return null;
    }

    public Set<Integer> sigma() {
        Set<Integer> sigma = new HashSet<Integer>();
        for (PathNode node : path) {
            if (node.type == PathNodeType.CharSet) {
                sigma.addAll(node.charSet);
            }
        }
        return sigma;
    }

    public Vector<Set<Integer>> getNormalizePath(boolean isPump) {
        normalize(isPump);
        return normalizePath;
    }

    public void normalize(boolean isPump) {
        if (isNormalized) {
            return;
        }
        normalizePath.clear();
        Vector<Set<Integer>> tmpNormalizePath = new Vector<Set<Integer>>();
        Vector<PathNode> satisfiedPath = DFS_FindSatisfiedPath(path, path.size()-1, isPump);
        if (satisfiedPath == null) return;
        for (PathNode node : satisfiedPath) {
            if (node.type == PathNodeType.CharSet) {
                tmpNormalizePath.add(node.charSet);
            }
        }
        normalizePath.addAll(tmpNormalizePath);
        isNormalized = true;
    }

    private Vector<PathNode> DFS_FindSatisfiedPath(Vector<PathNode> path, int index, boolean isPump) {
        if (index < 0) return path; // 已经找到了一个满足的路径
        Vector<PathNode> newPath = null;
        if (path.get(index).isSet()) {
            newPath = DFS_FindSatisfiedPath(path, index-1, isPump);
        }
        else if (path.get(index).isLookAround()) {
            PathNodeType lookaroundType = path.get(index).type;
            if(this.getPathSize() == 0) return null;
            for (Path lookaroundPath_ : path.get(index).lookaroundPath) {
                Path lookaroundPath = new Path(lookaroundPath_);
                Vector<Set<Integer>> normalizedLookaroundPath = lookaroundPath.getNormalizePath(false);
                Vector<PathNode> tmpPath = deepCopy(path);
                int i = index;
                for (Set<Integer> CharSet : normalizedLookaroundPath) {
                    // 跳过非set节点，移动到下一个set节点
                    if (lookaroundType == PathNodeType.LookAroundPos || lookaroundType == PathNodeType.LookAroundNeg) {
                        while (!tmpPath.get(i).isSet() && getPathSize() > 0) {
                            i++;
                            if (i >= tmpPath.size()) { // 超出范围
                                if (isPump) i = 0; // 如果是中缀，则可以循环，从头开始
                                else { // 不是中缀则不可循环，找不到满足的路径
                                    tmpPath = null;
                                    break;
                                }
                            }
                        }
                    }
                    else {
                        while (!tmpPath.get(i).isSet() && getPathSize() > 0) {
                            i--;
                            if (i < 0) { // 超出范围
                                if (isPump) i = tmpPath.size() - 1; // 如果是中缀，则可以循环，从尾开始
                                else { // 不是中缀则不可循环，找不到满足的路径
                                    tmpPath = null;
                                    break;
                                }
                            }
                        }
                    }

                    if (tmpPath == null) break;

                    Set<Integer> tmpSet = tmpPath.get(i).charSet;
                    if (lookaroundType == PathNodeType.LookAroundPos || lookaroundType == PathNodeType.LookAroundBehind) {
                        tmpSet.retainAll(CharSet);
                    }
                    else {
                        tmpSet.removeAll(CharSet);
                    }

                    if (tmpSet.size() == 0) {
                        tmpPath = null;
                        break;
                    }
                    else {
                        tmpPath.get(i).charSet = tmpSet;
                    }
                }

                if (tmpPath != null) {
                    newPath = DFS_FindSatisfiedPath(tmpPath, index-1, isPump); // 如果这一步可以满足，则继续搜索
                    if (newPath != null) break; // 如果后面的搜索找到了完整的满足路径，则直接返回
                }

                // 如果没有找到完整的满足路径，则继续搜索这一步的其他lookaround路径能否满足
            }
        }
        else if (path.get(index).isBound()) {
            PathNodeType boundType = path.get(index).type;
            if (getPathSize() == 0) return null;
            int i = index, j = index; // i是向后看的，j是向前看的
            boolean atBegin = false;
            boolean atEnd = false;
            while (!path.get(i).isSet() && getPathSize() > 0) { // i向后移动到下一个set节点
                i++;
                if (i >= path.size()) { // 超出范围，说明在开头
                    if (isPump) i = 0; // 如果是中缀，则可以循环，从头开始
                    else { // 当作在开头处理
                        atEnd = true;
                        break;
                    }
                }
            }
            while (!path.get(j).isSet() && getPathSize() > 0) { // j向前移动到下一个set节点
                j--;
                if (j < 0) { // 超出范围，说明在结尾
                    if (isPump) j = path.size() - 1; // 如果是中缀，则可以循环，从尾开始
                    else { // 当作在结尾处理
                        atBegin = true;
                        break;
                    }
                }
            }

            assert !(atBegin && atEnd); // 因为前面判断了平凡化后的长度，在开头和结尾都不可能出现

            if (!isPump && (atBegin || atEnd)) { // 如果不是中缀，且在开头或结尾
                Vector<PathNode> tmpPath = deepCopy(path);
                if (boundType == PathNodeType.WordBoundaryLower) {
                    if (atBegin) { // \b在开头，后面只能跟word
                        tmpPath.get(i).charSet.retainAll(regexUtils.word);
                        if (tmpPath.get(i).charSet.size() == 0) return null;
                    }
                    else { // \b在结尾，前面只能跟word
                        tmpPath.get(j).charSet.retainAll(regexUtils.word);
                        if (tmpPath.get(j).charSet.size() == 0) return null;
                    }
                }
                else if (boundType == PathNodeType.WordBoundaryUpper) {
                    if (atBegin) { // \B在开头，后面只能跟非word
                        tmpPath.get(i).charSet.removeAll(regexUtils.noneWord);
                        if (tmpPath.get(i).charSet.size() == 0) return null;
                    }
                    else { // \B在结尾，前面只能跟非word
                        tmpPath.get(j).charSet.removeAll(regexUtils.noneWord);
                        if (tmpPath.get(j).charSet.size() == 0) return null;
                    }
                }
                newPath = DFS_FindSatisfiedPath(tmpPath, index-1, isPump); // 如果这一步可以满足，则继续搜索
            }
            else {
                // 构造bound的满足路径
                Vector<Vector<Set<Integer>>> BoundPaths = new Vector<>();
                Vector<Set<Integer>> BoundPath = new Vector<>();
                if (boundType == PathNodeType.WordBoundaryLower) {
                    BoundPath.add(regexUtils.word);
                    BoundPath.add(regexUtils.noneWord);
                    BoundPaths.add(BoundPath);
                    BoundPath = new Vector<>();
                    BoundPath.add(regexUtils.noneWord);
                    BoundPath.add(regexUtils.word);
                    BoundPaths.add(BoundPath);
                }
                else if (boundType == PathNodeType.WordBoundaryUpper) {
                    BoundPath.add(regexUtils.noneWord);
                    BoundPath.add(regexUtils.noneWord);
                    BoundPaths.add(BoundPath);
                    BoundPath = new Vector<>();
                    BoundPath.add(regexUtils.word);
                    BoundPath.add(regexUtils.word);
                    BoundPaths.add(BoundPath);
                }

                for (Vector<Set<Integer>> boundPath : BoundPaths) {
                    Vector<PathNode> tmpPath = deepCopy(path);
                    tmpPath.get(j).charSet.retainAll(boundPath.get(0));
                    tmpPath.get(i).charSet.retainAll(boundPath.get(1));
                    if (tmpPath.get(i).charSet.size() == 0 || tmpPath.get(j).charSet.size() == 0) {
                        continue;
                    }
                    else {
                        newPath = DFS_FindSatisfiedPath(tmpPath, index - 1, isPump);
                        if (newPath != null) {
                            return newPath;
                        }
                    }
                }
            }
        }
        else {
            throw new RuntimeException("PathNodeType Error");
        }

        return newPath;
    }

    private Vector<PathNode> deepCopy(Vector<PathNode> path) {
        Vector<PathNode> newPath = new Vector<PathNode>();
        for (PathNode node : path) {
            newPath.add(new PathNode(node));
        }
        return newPath;
    }
}
