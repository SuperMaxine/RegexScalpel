package detector.Analysis.ReDosBean;

public class AttackBean {
    String prefix;
    public String pump;
    String suffix;
    int pumpTimes;
    boolean validate;
    public AttackBean(String prefix, String pump, String suffix, int pumpTimes, boolean validate) {
        this.prefix = prefix;
        this.pump = pump;
        this.suffix = suffix;
        this.pumpTimes = pumpTimes;
        this.validate = validate;
    }
}
