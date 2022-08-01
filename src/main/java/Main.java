import detector.DatasetTester;
import  detector.SingleTester;

public class Main {
    public static void main(String[] args) {
        SingleTester.Test(false, "a*a*b");
        DatasetTester.Test("data/input/CVE415-SOLA-DA.txt", "data/output/CVE415-SOLA-DA.txt");
    }
}
