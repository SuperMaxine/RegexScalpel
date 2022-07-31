package detector.Bean;


import java.util.ArrayList;

public class ReDoSBean {
    private String regex;
    private Integer id;
    private boolean reDoS;
    private ArrayList<AttackBean> attackBeanList;
    private AttackType type;

    public ReDoSBean() {
        this.reDoS = false;
        attackBeanList = new ArrayList<>();
    }

    public ReDoSBean(String regex, int id) {
        this.regex = regex;
        this.id = id;
        this.reDoS = false;
        this.attackBeanList = new ArrayList<>();
    }

    public boolean isReDoS() {
        return reDoS;
    }

    public void setReDoS(boolean reDoS) {
        this.reDoS = reDoS;
    }

    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    public ArrayList<AttackBean> getAttackBeanList() {
        return attackBeanList;
    }

    public void setAttackBeanList(ArrayList<AttackBean> attackBeanList) { this.attackBeanList = attackBeanList; }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    // public int getVul() {
    //     for (int i = 0; i < attackBeanList.size(); i++) {
    //         if (attackBeanList.get(i).isAttackSuccess()) {
    //             vul++;
    //         }
    //     }
    //     return vul;
    // }

}
