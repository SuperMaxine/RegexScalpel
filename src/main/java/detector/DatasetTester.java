package detector;

import cn.ac.ios.Bean.Pair;
import cn.ac.ios.Utils.Utils;
import detector.Analysis.Analysis;
import detector.Analysis.RepairType;
import org.apache.commons.io.FileUtils;
import regex.Analyzer;
import regex.Path;

import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DatasetTester {
    public static void main(String[] args) {
        // print test.txt line by line from data/input
        String inputFile = "data/input/CVE415-SOLA-DA.txt";
        String outputFile = "data/output/CVE415-SOLA-DA.txt";
        // String inputFile = "data/input/NQ.txt";
        // String outputFile = "data/output/NQ.txt";
        File file = new File(outputFile);
        // // delete output file is exists
        // if (file.exists()) {
        //     file.delete();
        // }

        List<String> lines = null;
        try {
            lines =  FileUtils.readLines(new File(inputFile), "utf-8");
        } catch (IOException e) {
            e.printStackTrace();
        }

        int jump = 121;

        int count = 0;
        for (String line : lines) {
            count += 1;
            if (count < jump) {
                continue;
            }
            // else if (count == jump) {
            //     Utils.appendWriteFileLine(outputFile, line);
            // }
            else {

                // System.out.println("id:" + count);
                //
                // // line = PreProcess.preProcess(line);
                // // Pattern p = Pattern.compile(line);
                // // Tree t = new Tree(p.root);
                // // String regex = t.generateRegex(t.root);
                // // // Analysis.Analysis(t);
                // // Analyzer a = new Analyzer(t);
                // // Utils.appendWriteFileLine(outputFile, regex);
                // Analysis.Analysis(line);

                // log start time
                long start = System.currentTimeMillis();

                final String[] result_out = {""};
                final boolean[] end = {false};
                ExecutorService executorService = Executors.newCachedThreadPool();
                int finalCount = count;
                executorService.execute(new Runnable() {
                    @Override
                    public void run() {
                        // result[0] = SingleTester.test(finalCount, line);
                        String regex_repaired = "";
                        String regex = line;
                        int count = 0;

                        // 调试显示
                        System.out.println("-----------------------------------------------------");
                        System.out.println("Test " + finalCount + ": " + regex);
                        // print date and time
                        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
                        Date date = new Date();
                        System.out.println(dateFormat.format(date));
                        System.out.println("-----------------------------------------------------");
                        do {
                            Vector<Pair<String, RepairType>> result = null;
                            try {
                                result = Analysis.Analysis(regex, count);
                            }
                            catch (Exception e) {
                                e.printStackTrace();
                                break;
                            }
                            if (result.size() == 0) {
                                break;
                            }

                            // 从result中随机选择一个作为regex_repaired
                            int index = (int) (Math.random() * result.size());
                            regex_repaired = result.get(index).getKey();

                            // // 始终挑选第一个
                            // regex_repaired = result.get(0).getKey();

                            System.out.println("repaired: "+regex_repaired + "\n");
                            regex = regex_repaired;
                            result_out[0] = regex_repaired;
                            count++;
                        } while (!regex_repaired.equals("") && count < 10);

                        System.out.println("final regex: "+regex);
                        end[0] = true;
                    }
                });
                // try {
                //     Thread.sleep(30000);
                // } catch (InterruptedException e) {
                //     e.printStackTrace();
                // }
                long current = System.currentTimeMillis();
                while(!end[0] && current - start < 30000) {
                    current = System.currentTimeMillis();
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        // e.printStackTrace();
                        System.out.println("线程请求中断");
                        return;
                    }
                }

                // 停止executorService中的所有线程，并销毁executorService
                executorService.shutdownNow();

                Utils.appendWriteFileLine(outputFile, result_out[0]==""?line:result_out[0]);
            }
        }
    }

    public static void Test(String inputFile, String outputFile) {
        File file = new File(outputFile);
        // delete output file is exists
        if (file.exists()) {
            file.delete();
        }

        List<String> lines = null;
        try {
            lines =  FileUtils.readLines(new File(inputFile), "utf-8");
        } catch (IOException e) {
            e.printStackTrace();
        }

        int jump = 121;

        int count = 0;
        for (String line : lines) {
            count += 1;
            if (count < jump) {
                continue;
            }
            else {
                long start = System.currentTimeMillis();

                final String[] result_out = {""};
                final boolean[] end = {false};
                ExecutorService executorService = Executors.newCachedThreadPool();
                int finalCount = count;
                executorService.execute(new Runnable() {
                    @Override
                    public void run() {
                        String regex_repaired = "";
                        String regex = line;
                        int count = 0;

                        // 调试显示
                        System.out.println("-----------------------------------------------------");
                        System.out.println("Test " + finalCount + ": " + regex);
                        // print date and time
                        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
                        Date date = new Date();
                        System.out.println(dateFormat.format(date));
                        System.out.println("-----------------------------------------------------");
                        do {
                            Vector<Pair<String, RepairType>> result = null;
                            try {
                                result = Analysis.Analysis(regex, count);
                            }
                            catch (Exception e) {
                                e.printStackTrace();
                                break;
                            }
                            if (result.size() == 0) {
                                break;
                            }

                            // 从result中随机选择一个作为regex_repaired
                            int index = (int) (Math.random() * result.size());
                            regex_repaired = result.get(index).getKey();

                            System.out.println("repaired: "+regex_repaired + "\n");
                            regex = regex_repaired;
                            result_out[0] = regex_repaired;
                            count++;
                        } while (!regex_repaired.equals("") && count < 10);

                        System.out.println("final regex: "+regex);
                        end[0] = true;
                    }
                });

                long current = System.currentTimeMillis();
                while(!end[0] && current - start < 30000) {
                    current = System.currentTimeMillis();
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        // e.printStackTrace();
                        System.out.println("线程请求中断");
                        return;
                    }
                }

                // 停止executorService中的所有线程，并销毁executorService
                executorService.shutdownNow();

                Utils.appendWriteFileLine(outputFile, result_out[0]==""?line:result_out[0]);
            }
        }
    }
}
