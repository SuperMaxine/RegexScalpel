package regex;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Vector;
import java.util.Set;

public class Path {
    Vector<PathNode> path;
    Vector<Vector<Set<Integer>>> realPaths;
    int realCharCount;
    boolean generatedRealPath;

    Path() {
        path = new Vector<>();
        realCharCount = 0;
        generatedRealPath = false;
    }

    Path(Path p) {
        path = new Vector<PathNode>(p.getPath());
        if (realPaths!=null) realPaths = new Vector<Vector<Set<Integer>>>(p.realPaths);
        realCharCount = p.realCharCount;
        generatedRealPath = p.generatedRealPath;
    }

    public Vector<PathNode> getPath() {
        return path;
    }

    public Vector<Vector<Set<Integer>>> getRealPaths(boolean isPump) {
        // TODO: 并未实现实际功能
        realPaths = new Vector<>();
        if (!generatedRealPath) {

            // Vector<Set<Integer>> tmpRealPath = new Vector<>();
            // for (PathNode node : path) {
            //     if (node.isSet()) {
            //         tmpRealPath.add(node.getCharSet());
            //     }
            // }
            // generatedRealPath = true;
            //
            // realPaths.add(tmpRealPath);

            Vector<Set<Integer>> tmpRealPath = new Vector<>();
            Vector<PathNode> SatisfyPath = returnSatisfyPath(path, path.size() - 1, isPump);
            if (SatisfyPath == null) return realPaths;
            for (PathNode tmpPath : SatisfyPath) {
                if (threadInterrupt()) return null;
                if (tmpPath.isSet()) {
                    tmpRealPath.add(tmpPath.getCharSet());
                }
            }

            realPaths.add(tmpRealPath);

        }
        return realPaths;
    }

    private Vector<PathNode> returnSatisfyPath(Vector<PathNode> path, int index, boolean isPump) {
        if (threadInterrupt()) return null;
        if (index < 0) return path;
        Vector<PathNode> newPath = null;
        if (path.get(index).isSet()) {
            newPath = returnSatisfyPath(path, index - 1, isPump);
        }
        else if (path.get(index).isLookaround()) {
            if (this.realCharCount == 0) return null;
            for (Path lookaroundPath_ : path.get(index).getLookaroundPath()) {
                if (threadInterrupt()) return null;
                Path lookaroundPath = new Path(lookaroundPath_);
            // for (int k = 0; k < path.get(index).getLookaroundPath().size(); k++) {
            //     Path lookaroundPath = new Path(path.get(index).getLookaroundPath().get(k));
            // Iterator<Path> it = path.get(index).getLookaroundPath().iterator();
            // while (it.hasNext()) {
            //     Path lookaroundPath = it.next();
                for (Vector<Set<Integer>> realLookaroundPath : lookaroundPath.getRealPaths(false)) {
                    if (threadInterrupt()) return null;
                    Vector<PathNode> tmpPath = copyPath(path);
                    int i = index;
                    for (Set<Integer> realCharSet : realLookaroundPath) {
                        if (threadInterrupt()) return null;
                        if (tmpPath.get(index).getLookaroundType() == Analyzer.lookaroundType.Pos || tmpPath.get(index).getLookaroundType() == Analyzer.lookaroundType.Neg) {
                            while (!tmpPath.get(i).isSet() && this.realCharCount > 0) {
                                if (threadInterrupt()) return null;
                                i++;
                                if (i >= tmpPath.size()) {
                                    if (isPump) i = 0;
                                    else {
                                        tmpPath = null;
                                        break;
                                    }
                                }
                            }
                        }
                        else {
                            while (!tmpPath.get(i).isSet()) {
                                if (threadInterrupt()) return null;
                                i--;
                                if (i < 0) {
                                    if (isPump) i = tmpPath.size() - 1;
                                    else {
                                        tmpPath = null;
                                        break;
                                    }
                                }
                            }
                        }

                        if (tmpPath != null) {
                            Set<Integer> tmpSet = tmpPath.get(i).getCharSet();
                            if (tmpPath.get(index).getLookaroundType() == Analyzer.lookaroundType.Pos || tmpPath.get(index).getLookaroundType() == Analyzer.lookaroundType.Behind) {
                                tmpSet.retainAll(realCharSet);
                            }
                            else {
                                tmpSet.removeAll(realCharSet);
                            }
                            if (tmpSet.size() == 0) {
                                tmpPath = null;
                                break;
                            }
                            else {
                                tmpPath.get(i).setCharSet(tmpSet);
                            }
                        }
                    }
                    if (tmpPath != null) {
                        newPath = returnSatisfyPath(tmpPath, index - 1, isPump);
                        if (newPath == null) continue;
                        break;
                    }
                    else {
                        continue;
                    }
                }
                if (newPath != null) break;
            }
        }
        else if (path.get(index).isBound()) {
            if (this.realCharCount == 0) return null;
            // newPath = returnSatisfyPath(path, index - 1, isPump);
            int i = index, j = index;
            boolean atBegin = false;
            boolean atEnd = false;
            while (!path.get(i).isSet() && this.realCharCount > 0) {
                if (threadInterrupt()) return null;
                i++;
                if (i >= path.size()) {
                    if (isPump) i = 0;
                    else {
                        atBegin = true;
                        break;
                    }
                }
            }
            while (!path.get(j).isSet()) {
                if (threadInterrupt()) return null;
                j--;
                if (j < 0) {
                    if (isPump) j = path.size() - 1;
                    else {
                        atEnd = true;
                        break;
                    }
                }
            }

            if (atBegin && atEnd) {
                return null;
            }

            if (!isPump && (atBegin || atEnd)) {
                Vector<PathNode> tmpPath = copyPath(path);
                if (tmpPath.get(index).getbType() == PathNode.boundType.lower) {
                    if (atBegin) {
                        tmpPath.get(j).getCharSet().retainAll(Analyzer.word);
                        if (tmpPath.get(j).getCharSet().size() == 0) {
                            return null;
                        }
                    }
                    else {
                        tmpPath.get(i).getCharSet().retainAll(Analyzer.word);
                        if (tmpPath.get(i).getCharSet().size() == 0) {
                            return null;
                        }
                    }
                }
                else if (tmpPath.get(index).getbType() == PathNode.boundType.upper) {
                    if (atBegin) {
                        tmpPath.get(j).getCharSet().retainAll(Analyzer.noneWord);
                        if (tmpPath.get(j).getCharSet().size() == 0) {
                            return null;
                        }
                    }
                    else {
                        tmpPath.get(i).getCharSet().retainAll(Analyzer.noneWord);
                        if (tmpPath.get(i).getCharSet().size() == 0) {
                            return null;
                        }
                    }
                }
                newPath = returnSatisfyPath(tmpPath, index - 1, isPump);
            }
            else {
                Vector<Vector<Set<Integer>>> BoundPaths = new Vector<>();
                Vector<Set<Integer>> BoundPath = new Vector<>();
                if (path.get(index).getbType() == PathNode.boundType.lower) {
                    BoundPath.add(Analyzer.word);
                    BoundPath.add(Analyzer.noneWord);
                    BoundPaths.add(BoundPath);
                    BoundPath = new Vector<>();
                    BoundPath.add(Analyzer.noneWord);
                    BoundPath.add(Analyzer.word);
                    BoundPaths.add(BoundPath);
                }
                else if (path.get(index).getbType() == PathNode.boundType.upper) {
                    BoundPath.add(Analyzer.noneWord);
                    BoundPath.add(Analyzer.noneWord);
                    BoundPaths.add(BoundPath);
                    BoundPath = new Vector<>();
                    BoundPath.add(Analyzer.word);
                    BoundPath.add(Analyzer.word);
                    BoundPaths.add(BoundPath);
                }

                for (Vector<Set<Integer>> boundPath : BoundPaths) {
                    if (threadInterrupt()) return null;
                    Vector<PathNode> tmpPath = copyPath(path);
                    tmpPath.get(i).getCharSet().retainAll(boundPath.get(0));
                    tmpPath.get(j).getCharSet().retainAll(boundPath.get(1));
                    if (tmpPath.get(i).getCharSet().size() == 0 || tmpPath.get(j).getCharSet().size() == 0) {
                        continue;
                    }
                    else {
                        newPath = returnSatisfyPath(tmpPath, index - 1, isPump);
                        if (newPath != null) {
                            return newPath;
                        }
                    }
                }
            }

        }
        return newPath;
    }

    public Vector<PathNode> copyPath(Vector<PathNode> path) {
        Vector<PathNode> newPath = new Vector<>();
        for (PathNode node : path) {
            if (threadInterrupt()) return null;
            newPath.add(new PathNode(node));
        }
        return newPath;
    }

    public void add(PathNode node) {
        path.add(node);
        if (node.isSet()) {
            realCharCount++;
        }
    }

    public void addAll(Path p) {
        path.addAll(p.getPath());
        realCharCount += p.realCharCount;
    }

    public int getSize() {
        return path.size();
    }

    public int getRealCharSize() {
        return realCharCount;
    }

    boolean threadInterrupt() {
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...8");
            return true;
        }
        return false;
    }
}
