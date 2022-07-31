package detector.Analysis.ReDosBean;

import detector.Tree.Nodes.ConnectNode;
import detector.Tree.Nodes.LoopNode;

public class QOABean extends ReDosBean {
    public LoopNode r1;
    public LoopNode r2;
    public ConnectNode commonFather;
    public LoopNode outsideLoopNode;
    public qoaType type;
    public enum qoaType {
        QOA1, QOA2, QOA3, QOA4, QOA5
    }

    public QOABean(LoopNode r1, LoopNode r2, qoaType type) {
        this.r1 = r1;
        this.r2 = r2;
        this.type = type;
    }

    public void setOutsideLoopNode(LoopNode outsideLoopNode) {
        this.outsideLoopNode = outsideLoopNode;
    }
}
