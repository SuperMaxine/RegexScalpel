package detector.Analysis.ReDosBean;

import detector.Tree.Nodes.LoopNode;

public class SLQBean extends ReDosBean{
    public LoopNode r;
    public LoopNode r_q2;

    public slqType type;

    public enum slqType {
        SLQ1, SLQ2, SLQ3, SLQ4, SLQ5
    }

    public SLQBean(LoopNode r, slqType type) {
        this.r = r;
        this.type = type;
    }

    public void setR_q2(LoopNode r_q2) {
        this.r_q2 = r_q2;
    }
}
