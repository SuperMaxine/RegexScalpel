package detector.Analysis.ReDosBean;

import detector.Tree.Nodes.LoopNode;

public class NQBean extends ReDosBean {
    public LoopNode outsideLoopNode;
    public LoopNode insideLoopNode;

    public NQBean(LoopNode outsideLoopNode, LoopNode insideLoopNode) {
        super();
        this.outsideLoopNode = outsideLoopNode;
        this.insideLoopNode = insideLoopNode;
    }
}
