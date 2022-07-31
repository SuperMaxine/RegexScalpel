package detector.Analysis.ReDosBean;

import detector.Path.Path;
import detector.Tree.Nodes.BranchNode;
import detector.Tree.Nodes.LoopNode;
import detector.Tree.Nodes.TreeNode;

import java.util.Set;
import java.util.Vector;

public class QODBean extends ReDosBean{
    public LoopNode outsideLoopNode;
    public BranchNode insideBranchNode;
    public qodType type;

    public Vector<Path> iterations;
    public TreeNode rp;
    public Vector<Set<Integer>> alpha1;
    public Vector<Set<Integer>> alpha2;

    public enum qodType {
        QOD1, QOD2
    }

    public QODBean(LoopNode outsideLoopNode, BranchNode insideBranchNode) {
        super();
        this.outsideLoopNode = outsideLoopNode;
        this.insideBranchNode = insideBranchNode;
        iterations = new Vector<>();
    }

    public void setType(qodType type) {
        this.type = type;
    }

    public void setIterations(Vector<Path> iterations) {
        this.iterations = iterations;
    }

    public void setRp(TreeNode rp) {
        this.rp = rp;
    }

    public void setAlpha(Vector<Set<Integer>> alpha1, Vector<Set<Integer>> alpha2) {
        this.alpha1 = alpha1;
        this.alpha2 = alpha2;
    }
}
