package cn.ac.ios;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * @author pqc
 */
public class TestUtils {

    public static void main(String[] args) throws IOException {

//        Set<Integer> set = new HashSet<>();
//        set.addAll(getIds("data/expr/regexlib_only_redos_true_s_java_10000_0_2021_08_17_22_59_15.txt"));
//        set.addAll(getIds("data/expr/regexlib_only_redos_true_s_java_01000_0_2021_08_17_23_05_38.txt"));
//        set.addAll(getIds("data/expr/regexlib_only_redos_true_s_java_00100_0_2021_08_17_23_23_04.txt"));
//        set.addAll(getIds("data/expr/regexlib_only_redos_true_s_java_00010_0_2021_08_18_00_24_34.txt"));
//        set.addAll(getIds("data/expr/regexlib_only_redos_true_s_java_00001_0_2021_08_18_10_55_19.txt"));
//        set.removeAll(getIds("data/expr/regexlib_only_redos_true_s_java_11111_0_2021_08_18_12_59_05.txt"));
//        System.out.println(set.size());
//        System.out.println(set);

//        ArrayList<Integer> list = new ArrayList<>(set);
//        ArrayList<Integer> old =  getIds("data/expr/snort_only_redos_true_s_java_11111_0_2021_07_27_20_43_28.txt");
//        System.out.println(old.size());
//        old.removeAll(list);
//        System.out.println(old.size());

        System.out.println(getIncrease("data/expr/regexlib_only_redos_true_s_java_10000_0_2021_08_22_13_58_44.txt",
                "data/expr/regexlib_only_redos_true_s_java_10000_0_2021_08_22_13_20_54.txt"));

    }

    /**
     * 获取正则id
     *
     * @param fileName
     * @return
     * @throws IOException
     */
    public static ArrayList<Integer> getIds(String fileName) throws IOException {
        ArrayList<Integer> list = new ArrayList<>();
        List<String> lines = FileUtils.readLines(new File(fileName), "utf-8");
        for (String line : lines) {
            if (line.startsWith("id:")) {
                list.add(Integer.parseInt(line.replace("id:", "")));
            }
        }
        return list;
    }

    /**
     * 获取新文件miss的id
     *
     * @param newFile
     * @param oldFile
     * @return
     * @throws IOException
     */
    public static ArrayList<Integer> getMiss(String newFile, String oldFile) throws IOException {
        ArrayList<Integer> newIds = getIds(newFile);
        ArrayList<Integer> oldIds = getIds(oldFile);
        oldIds.removeAll(newIds);
        oldIds.sort(Comparator.naturalOrder());
        return oldIds;
    }

    /**
     * 获取新文件新增的id
     *
     * @param newFile
     * @param oldFile
     * @return
     * @throws IOException
     */
    public static ArrayList<Integer> getIncrease(String newFile, String oldFile) throws IOException {
        ArrayList<Integer> newIds = getIds(newFile);
        ArrayList<Integer> oldIds = getIds(oldFile);
        newIds.removeAll(oldIds);
        newIds.sort(Comparator.naturalOrder());
        return newIds;
    }
}
