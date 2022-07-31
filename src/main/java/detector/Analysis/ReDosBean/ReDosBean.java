package detector.Analysis.ReDosBean;

public class ReDosBean {

    public AttackBean attackBean; // 用来存放成功的攻击信息，没有成功信息则为null
    public ReDosBean() {
        attackBean = null;
    }

    public void setAttackBean(AttackBean attackBean) {
        this.attackBean = attackBean;
    }
}