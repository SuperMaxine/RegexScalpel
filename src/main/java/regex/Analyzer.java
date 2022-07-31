package regex;

import cn.ac.ios.PreprocessingInterface;
import javafx.util.Pair;
import redos.regex.Pattern4Search;
import redos.regex.redosPattern;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author SuperMaxine
 */
public class Analyzer {
    private static final Pattern DotP = Pattern.compile(".");
    // private static final Pattern BoundP = Pattern.compile("\\b");
    private static final Pattern SpaceP = Pattern.compile("\\s");
    private static final Pattern noneSpaceP = Pattern.compile("\\S");
    private static final Pattern wordP = Pattern.compile("\\w");
    private static final Pattern AllP = Pattern.compile("[\\s\\S]");
    private static final Pattern noneWordP = Pattern.compile("\\W");
    private static final Pattern DefaultSmallCharSetP = Pattern.compile("[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\\\"#$%&'()*+,-./:;>=<?@\\[\\]^_`{|}~ \\t\\n\\r]");
    //获取特定类别的节点set
    static Set<Integer> Dot = null;
    // Set<Integer> Bound;
    static Set<Integer> Space = null;
    static Set<Integer> SpaceFull = null;
    static Set<Integer> noneSpace = null;
    static Set<Integer> word = null;
    static Set<Integer> All = null;
    static Set<Integer> noneWord = null;

    // private final boolean OneCouting = true;
       private boolean OneCouting = false;
    // private final boolean POA = true;
    private boolean POA = false;
       // private boolean SLQ = true;
    private boolean SLQ = false;

    // private final boolean debugPath = true;
    private final boolean debugPath = false;

    // private final boolean debugStep = true;
    private final boolean debugStep = false;

    private final boolean debugRegex = true;
    // private final boolean debugRegex = false;

    private final boolean debugStuck = true;
    // private final boolean debugStuck = false;

    // private final boolean debugFirstAndLast = true;
    private final boolean debugFirstAndLast = false;

    private final boolean realTest = true;
    // private final boolean realTest = false;

    // private final boolean SpaceFullSet = true;
    private final boolean SpaceFullSet = false;


    long startTime;
    long endTime;

    String raw_regex;
    String regex;
    int maxLength;
    private Set<Integer> fullSmallCharSet;
    private Map<Pattern.CharProperty, Set<Integer>> bigCharSetMap;
    private HashSet<Pattern.CharProperty> charPropertySet;
    private Pattern4Search testPattern = null;
    private redosPattern testPattern4Search = null;
    public boolean attackable = false;
    public String attackMsg = "";

    // 建立FinalTree所需的全局变量
    Pattern.Node lastNode;
    private Map<Integer, Integer> groupIndex2LocalIndex; // GroupHead内的标号是localIndex递增，但BackRef所使用的是groupIndex，在GroupTail中可以拿到localIndex和groupIndex的对应
    private Map<Integer, LeafNode> groupStartNodesMap; // 以localIndex为索引，记录了所有group开始的节点
    private Vector<LeafNode> backRefNodes; // 存储所有反向引用的节点，用于后续以实际捕获组的copy替换
    Vector<LeafNode> lookaroundAtLast; // 存储从末尾向前数在遇到"实际字符"前的所有lookaround，用于提取内容或删除后在末尾添加[\s\S]*

    // 生成路径需要的结构
    LeafNode root;
    private Vector<LeafNode> countingNodes;
    private Map<LeafNode, Vector<Vector<Set<Integer>>>> countingPrePaths;
    private Map<LeafNode, String> countingPreRegex;
    private int id;
    private Map<Integer, Set<Integer>> id2childNodes;


    // 优化相关
    // 自动字符集大小
    boolean need256 = false;
    boolean need65536 = false;
    // 是否有特性决定枚举方式
    boolean haveAdvancedFeatures = false;
    // countingNode去除Dot
    LeafNode DotNode = null;

    public Analyzer(String raw_regex, int maxLength, int id, String testType) {
        this.raw_regex = raw_regex;
        System.out.println("raw_regex: " + raw_regex);
        // 预处理
        this.regex = PreprocessingInterface.preprocess(raw_regex);

        // this.regex = raw_regex;

        System.out.println("regex: " + regex);
        this.maxLength = maxLength;
        fullSmallCharSet = new HashSet<>();
        bigCharSetMap = new HashMap<>();
        charPropertySet = new HashSet<>();

        if (testType.equals("OneCouting"))OneCouting = true;
        else if (testType.equals("POA"))POA = true;
        else if (testType.equals("SLQ"))SLQ = true;


        if (SLQ) testPattern4Search = redosPattern.compile(regex);
        else testPattern = Pattern4Search.compile(regex);

        groupIndex2LocalIndex = new HashMap<>();
        groupStartNodesMap = new HashMap<>();
        backRefNodes = new Vector<>();
        lookaroundAtLast = new Vector<>();

        countingNodes = new Vector<>();
        countingPrePaths = new HashMap<>();
        countingPreRegex = new HashMap<>();
        id2childNodes = new HashMap<>();

        // 记录开始时间
        startTime = System.currentTimeMillis();
        //  建立原始树
        Pattern rawPattern = Pattern.compile(regex);
        root = buildTree(rawPattern.root, new HashSet<>());
        // System.out.println("flowchart TD");
        // printTree(root, true);
        if (threadInterrupt("", false)) return;

        // 对原始树进行优化，生成新树
        root = buildFinalTree(root);

        // System.out.println("\n\n-----------------------\n\n\nflowchart TD");
        // printTree(root, true);
        if (threadInterrupt("", false)) return;

        endTime = System.currentTimeMillis();
        System.out.println("id:"+id+",Build tree cost time: " + (endTime - startTime) + "ms");
        startTime = endTime;

        generateStandardCharSets();
        generateAllCharSet();
        scanAllPath(root, false);
        generateAllBigCharSet();
        countingNodes.remove(DotNode);

        // generateAllPath(root);
        // System.out.println("\n\n-----------------------\n\n\nflowchart TD");
        printTree(root, true);
        // 记录结束时间
        endTime = System.currentTimeMillis();
        System.out.println("id:"+id+",scanAllPath cost time: " + (endTime - startTime) + "ms");

        if (threadInterrupt("generate all path time out", true)) return;


        // --------------------生成树阶段结束，对漏洞进行攻击阶段开始-----------------------------

        // 生成前缀路径
        // for (LeafNode node : countingNodes) {
        //     if(Thread.currentThread().isInterrupted()){
        //         System.out.println("线程请求中断...");
        //         if (debugPath) {
        //             try {
        //                 attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString("generate all pre path time out".getBytes("utf-8"));
        //                 BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
        //                 writer.write(id + "," + attackMsg + "\n");
        //                 writer.close();
        //             } catch (IOException e) {
        //                 e.printStackTrace();
        //             }
        //         }
        //         return;
        //     }
        //     String preRegex = generatePreRegex(node);
        //     Vector<Vector<Set<Integer>>> prePaths = generatePrePath(node);
        //     Collections.sort((prePaths), new Comparator<Vector<Set<Integer>>>() {
        //         @Override
        //         public int compare(Vector<Set<Integer>> o1, Vector<Set<Integer>> o2) {
        //             return o1.size() - o2.size();
        //         }
        //     });
        //     countingPrePaths.put(node, prePaths);
        //     countingPreRegex.put(node, preRegex);
        //     // System.out.println("id: " + node.id + " preRegex: " + preRegex);
        //     // System.out.println("\n" + node.toString());
        //     // System.out.println(printPaths(prePaths, false));
        //     // Enumerator pre = new Enumerator(prePaths.get(0));
        //     // while(pre.hasNext()) {
        //     //     System.out.println(pre.next());
        //     // }
        // }


        if (threadInterrupt("generate all path time out", true)) return;

        final int[] ThreadsNum = {0};

        if (OneCouting) {
            final boolean[] getResult = {false};
            ExecutorService executorService = Executors.newCachedThreadPool();

            for (LeafNode node : countingNodes) {

                executorService.execute(new Runnable() {
                    @Override
                    public void run() {
                        ThreadsNum[0]++;
                        // synchronized (countingPrePaths) {
                            // System.out.println("----------------------------------------------------------\nnode regex: " + node.SelfRegex + "\npumpPaths:\n" + printPaths(node.getRealPaths(), false) + "\n");
                            if (debugStuck) System.out.println("node: " + node.id + ",regex:" + node.SelfRegex);
                            for (int i = 0 ; i < node.getRealPaths().size() && !Thread.currentThread().isInterrupted(); i++) {
                                for (int j = i + 1; j < node.getRealPaths().size() && !Thread.currentThread().isInterrupted(); j++) {
                                    Vector<Set<Integer>> pumpPath = getPathCompletelyOverLap(node.getRealPaths().get(i), node.getRealPaths().get(j));
                                    if(pumpPath.size() != 0) {
                                        synchronized (countingPrePaths) {
                                            if (countingPrePaths.get(node) == null) {
                                                Vector<Path> prePaths = generatePrePath(node);
                                                Collections.sort((prePaths), new Comparator<Path>() {
                                                    @Override
                                                    public int compare(Path o1, Path o2) {
                                                        return o1.getRealCharSize() - o2.getRealCharSize();
                                                    }
                                                });
                                                Vector<Vector<Set<Integer>>> realPrePaths = new Vector<>();
                                                for (Path path : prePaths) {
                                                    realPrePaths.addAll(path.getRealPaths(false));
                                                }
                                                countingPrePaths.put(node, realPrePaths);
                                            }
                                        }
                                        for (Vector<Set<Integer>> prePath : countingPrePaths.get(node)) {
                                            if (threadInterrupt("", false)) return;

                                            Enumerator preEnum = new Enumerator(prePath);
                                            Enumerator pumpEnum = new Enumerator(pumpPath);
                                            if (dynamicValidate(preEnum, pumpEnum, VulType.OneCounting)) {
                                                getResult[0] = true;
                                                ThreadsNum[0]--;
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        // }
                        ThreadsNum[0]--;
                    }
                });

            }


            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            while(!getResult[0] && !Thread.currentThread().isInterrupted() && ThreadsNum[0] != 0) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    // e.printStackTrace();
                    System.out.println("线程请求中断...1");
                    return;
                }
            }

            // 停止executorService中的所有线程，并销毁executorService
            executorService.shutdownNow();

            System.out.println("[*] OneCouting finished");
        }

        if (POA) {
            final boolean[] getResult = {false};
            ExecutorService executorService = Executors.newCachedThreadPool();

            for (int i = 0; i < countingNodes.size() && !Thread.currentThread().isInterrupted(); i++) {
                for (int j = i + 1; j < countingNodes.size() && !Thread.currentThread().isInterrupted(); j++) {
                    LeafNode node1 = countingNodes.get(i);
                    LeafNode node2 = countingNodes.get(j);

                    executorService.execute(new Runnable() {
                        @Override
                        public void run() {
                            ThreadsNum[0]++;
                            // synchronized (countingPrePaths) {
                                if (debugPath)
                                    attackMsg += "----------------------------------------------------------\nnode1(id:" + node1.id + ") regex:\n" + node1.SelfRegex + "\nnode2(id:" + node2.id + ") regex:\n" + node2.SelfRegex + "\n";


                                // 判断嵌套、直接相邻，以及夹着内容相邻
                                // 嵌套结构跳过不测
                                if (isNode1ChildOfNode2(node1, node2) || isNode1ChildOfNode2(node2, node1)) return;

                                else {
                                    if (debugStuck) System.out.println("node1: " + node1.id + " node2: " + node2.id);
                                    // 找到两者的公共父节点，然后求出两者之间夹着的路径
                                    Pair<Vector<Vector<Set<Integer>>>, LeafNode> midPathsAndFrontNode = getMidAndFrontNode(node1, node2);
                                    if (midPathsAndFrontNode == null) return;

                                    // Vector<Vector<Set<Integer>>> debugMidPaths = midPathsAndFrontNode.getKey();

                                    // 说明两者直接相邻
                                    if (midPathsAndFrontNode.getKey().size() == 0 || midPathsAndFrontNode.getKey().get(0).size() == 0) {
                                        // if (midPathsAndFrontNode.getKey().size() == 0) {

                                        // 通过First和Last判断是否可以跳过
                                        Set<Integer> firstIntersection = new HashSet<>(setsIntersection(node1.first, node2.first));
                                        Set<Integer> lastIntersection = new HashSet<>(setsIntersection(node1.last, node2.last));
                                        if (firstIntersection.size() == 0 || lastIntersection.size() == 0) return;

                                        if (debugPath)
                                            attackMsg += "POA-Direct Adjacent:\nnode1 paths\n" + printPaths(node1.getRealPaths(), false) + "\nnode2 paths\n" + printPaths(node2.getRealPaths(), false) + "\n\n";
                                        for (Vector<Set<Integer>> path1 : node1.getRealPaths()) {
                                            if (path1.size() == 0) continue;

                                            // 通过first和last判断是否可以跳过这条路径
                                            Vector<Set<Integer>> tmpPath = new Vector<>(path1);
                                            tmpPath.set(0, setsIntersection(tmpPath.get(0), firstIntersection));
                                            tmpPath.set(tmpPath.size() - 1, setsIntersection(tmpPath.get(tmpPath.size() - 1), lastIntersection));
                                            if (tmpPath.get(0).size() == 0 && tmpPath.get(tmpPath.size() - 1).size() == 0)
                                                continue;
                                            else path1 = tmpPath;

                                            for (Vector<Set<Integer>> path2 : node2.getRealPaths()) {
                                                if (threadInterrupt("\nTraversing paths time out\n", true)) return;
                                                if (path2.size() == 0 || path1.size() != path2.size()) continue;

                                                Vector<Set<Integer>> pumpPath = getPathCompletelyOverLap(path1, path2);
                                                if (pumpPath.size() != 0) {
                                                    if (debugPath)
                                                        attackMsg += "\npath1:\n" + printPath(path1, false) + "\npath2:\n" + printPath(path2, false) + "\npumpPath:\n" + printPath(pumpPath, false) + "\nprePaths:\n" + printPaths(countingPrePaths.get(midPathsAndFrontNode.getValue()), false) + "\n";
                                                    if (realTest) {
                                                        synchronized (countingPrePaths) {
                                                            if (countingPrePaths.get(midPathsAndFrontNode.getValue()) == null) {
                                                                Vector<Path> prePaths = generatePrePath(midPathsAndFrontNode.getValue());
                                                                Collections.sort((prePaths), new Comparator<Path>() {
                                                                    @Override
                                                                    public int compare(Path o1, Path o2) {
                                                                        return o1.getRealCharSize() - o2.getRealCharSize();
                                                                    }
                                                                });
                                                                Vector<Vector<Set<Integer>>> prePathsRealPaths = new Vector<>();
                                                                for (Path path : prePaths) {
                                                                    prePathsRealPaths.addAll(path.getRealPaths(false));
                                                                }
                                                                countingPrePaths.put(midPathsAndFrontNode.getValue(), prePathsRealPaths);
                                                            }
                                                        }
                                                        for (Vector<Set<Integer>> prePath : countingPrePaths.get(midPathsAndFrontNode.getValue())) {
                                                            if (Thread.currentThread().isInterrupted()) {
                                                                System.out.println("线程请求中断...3");
                                                                return;
                                                            }
                                                            Enumerator preEnum = new Enumerator(prePath);
                                                            Enumerator pumpEnum = new Enumerator(pumpPath);
                                                            if (dynamicValidate(preEnum, pumpEnum, VulType.POA)) {
                                                                getResult[0] = true;
                                                                ThreadsNum[0]--;
                                                                return;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // 说明两者之间夹着内容，\w+0\d+
                                    else {

                                        // 判断是否有路径可以跳过
                                        // 通过First和Last判断是否可以跳过
                                        Set<Integer> firstIntersection = new HashSet<>(setsIntersection(node1.first, node2.first));
                                        Set<Integer> lastIntersection = new HashSet<>(setsIntersection(node1.last, node2.last));
                                        if (firstIntersection.size() == 0 || lastIntersection.size() == 0) return;

                                        synchronized (countingPrePaths) {
                                            if (countingPrePaths.get(midPathsAndFrontNode.getValue()) == null) {
                                                Vector<Path> prePaths = generatePrePath(midPathsAndFrontNode.getValue());
                                                Collections.sort((prePaths), new Comparator<Path>() {
                                                    @Override
                                                    public int compare(Path o1, Path o2) {
                                                        return o1.getRealCharSize() - o2.getRealCharSize();
                                                    }
                                                });
                                                Vector<Vector<Set<Integer>>> prePathsRealPaths = new Vector<>();
                                                for (Path path : prePaths) {
                                                    prePathsRealPaths.addAll(path.getRealPaths(false));
                                                }
                                                countingPrePaths.put(midPathsAndFrontNode.getValue(), prePathsRealPaths);
                                            }
                                        }
                                        Vector<Vector<Set<Integer>>> prePaths = countingPrePaths.get(midPathsAndFrontNode.getValue());
                                        Vector<Set<Integer>> pumpPath;
                                        LeafNode frontNode = midPathsAndFrontNode.getValue();
                                        LeafNode backNode = node1 == midPathsAndFrontNode.getValue() ? node2 : node1;

                                        if (debugPath)
                                            attackMsg += "POA-Nested:\nnode1 paths\n" + printPaths(node1.getRealPaths(), false) + "\nmidPaths:\n" + printPaths(midPathsAndFrontNode.getKey(), false) + "\nnode2 paths\n" + printPaths(node2.getRealPaths(), false) + "\n";

                                        // 新方法判断
                                        for (Vector<Set<Integer>> path1 : frontNode.getRealPaths()) {
                                            if (path1.size() == 0) continue;
                                            // 通过first和last判断是否可以跳过这条路径
                                            Vector<Set<Integer>> tmpPath = new Vector<>(path1);
                                            tmpPath.set(0, setsIntersection(tmpPath.get(0), firstIntersection));
                                            tmpPath.set(tmpPath.size() - 1, setsIntersection(tmpPath.get(tmpPath.size() - 1), lastIntersection));
                                            if (tmpPath.get(0).size() == 0 && tmpPath.get(tmpPath.size() - 1).size() == 0)
                                                continue;
                                            else path1 = tmpPath;

                                            // if (setsIntersection(path1.get(0), firstIntersection).size() == 0 && setsIntersection(path1.get(path1.size() - 1), lastIntersection).size() == 0) continue;

                                            for (Vector<Set<Integer>> path3 : backNode.getRealPaths()) {
                                                if (path3.size() == 0 || path3.size() != path1.size()) continue;
                                                // 通过first和last判断是否可以跳过这条路径
                                                // tmpPath = new Vector<>(path3);
                                                // tmpPath.set(0, setsIntersection(tmpPath.get(0), firstIntersection));
                                                // tmpPath.set(tmpPath.size() - 1, setsIntersection(tmpPath.get(tmpPath.size() - 1), lastIntersection));
                                                // if (tmpPath.get(0).size() == 0 && tmpPath.get(tmpPath.size() - 1).size() == 0) continue;
                                                // else
                                                //     path3 = tmpPath;

                                                Vector<Set<Integer>> overlap = getPathCompletelyOverLap(path1, path3);
                                                if (overlap.size() == 0) continue;

                                                for (Vector<Set<Integer>> path2 : midPathsAndFrontNode.getKey()) {
                                                    if (path2.size() == 0) continue;
                                                    if (path2.size() > overlap.size()) continue;
                                                    tmpPath = new Vector<>();
                                                    for (int k = 0; k < path2.size() && !Thread.currentThread().isInterrupted(); k++) {
                                                        Set<Integer> tmpCharSet = new HashSet<>(path2.get(k));
                                                        tmpCharSet.retainAll(overlap.get(k));
                                                        if (tmpCharSet.size() == 0) {
                                                            break;
                                                        }
                                                        else {
                                                            tmpPath.add(tmpCharSet);
                                                        }
                                                    }

                                                    boolean needTest = false;

                                                    // 长度相等只有完全重叠一种可能
                                                    if (path2.size() == overlap.size()) {
                                                        // 说明r2和overlap完全重叠
                                                        if (tmpPath.size() == overlap.size()) {
                                                            needTest = true;
                                                        }
                                                    }
                                                    // 长度小于还可能是前缀或后缀
                                                    else {
                                                        // 说明r2是overLap的前缀
                                                        if (tmpPath.size() == path2.size()) {
                                                            needTest = true;
                                                        }

                                                        if (!needTest) {
                                                            // r2是不是overLap的后缀需要重新测
                                                            tmpPath = new Vector<>();
                                                            int diff = overlap.size() - path2.size();
                                                /*
                                                0 1 2 3 4 5 size = 6
                                                      0 1 2 size = 3

                                                 */
                                                            for (int k = overlap.size() - 1; k >= diff && !Thread.currentThread().isInterrupted(); k--) {
                                                                Set<Integer> tmpCharSet = new HashSet<>(overlap.get(k));
                                                                tmpCharSet.retainAll(path2.get(k - diff));
                                                                if (tmpCharSet.size() == 0) {
                                                                    break;
                                                                }
                                                                else {
                                                                    tmpPath.add(tmpCharSet);
                                                                }
                                                            }
                                                            // 说明r2是overLap的后缀
                                                            if (tmpPath.size() == path2.size()) {
                                                                needTest = true;
                                                            }
                                                        }

                                                    }

                                                    if (needTest) {
                                                        for (Vector<Set<Integer>> prePath : prePaths) {
                                                            if (threadInterrupt("", false)) return;

                                                            Enumerator preEnum = new Enumerator(prePath);
                                                            Enumerator pumpEnum = new Enumerator(overlap);
                                                            if (dynamicValidate(preEnum, pumpEnum, VulType.POA)) {
                                                                getResult[0] = true;
                                                                ThreadsNum[0]--;
                                                                return;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // // \w+0 vs \d+
                                        // for (Vector<Set<Integer>> path1 : splicePath(frontNode.getPaths(), midPathsAndFrontNode.getKey())) {
                                        //     if (path1.size() == 0) continue;
                                        //     for (Vector<Set<Integer>> path2 : backNode.getPaths()) {
                                        //         if (threadInterrupt("\nTraversing paths time out\n", true)) return;
                                        //         if (path2.size() == 0 || path1.size() != path2.size()) continue;
                                        //
                                        //         pumpPath = getPathCompletelyOverLap(path1, path2);
                                        //         if (pumpPath.size() != 0) {
                                        //             if (debugPath) attackMsg += "\npath1:\n" + printPath(path1, false) + "\npath2:\n" + printPath(path2, false) + "\npumpPath:\n" + printPath(pumpPath, false) + "\nprePaths:\n" + printPaths(prePaths, false) + "\n";
                                        //             if (realTest) {
                                        //                 for (Vector<Set<Integer>> prePath : prePaths) {
                                        //                     if (threadInterrupt("", false)) return;
                                        //
                                        //                     Enumerator preEnum = new Enumerator(prePath);
                                        //                     Enumerator pumpEnum = new Enumerator(pumpPath);
                                        //                     if (dynamicValidate(preEnum, pumpEnum, VulType.POA)) return;
                                        //                 }
                                        //             }
                                        //         }
                                        //     }
                                        // }
                                        //
                                        // // \w+ vs 0\d+
                                        // for (Vector<Set<Integer>> path1 : splicePath(midPathsAndFrontNode.getKey(), backNode.getPaths())) {
                                        //     if (path1.size() == 0) continue;
                                        //     for (Vector<Set<Integer>> path2 : frontNode.getPaths()) {
                                        //         if (threadInterrupt("\nTraversing paths time out\n", true)) return;
                                        //         if (path2.size() == 0 || path1.size() != path2.size()) continue;
                                        //
                                        //         pumpPath = getPathCompletelyOverLap(path1, path2);
                                        //         if (pumpPath.size() != 0) {
                                        //             if (debugPath) attackMsg += "\npath1:\n" + printPath(path1, false) + "\npath2:\n" + printPath(path2, false) + "\npumpPath:\n" + printPath(pumpPath, false) + "\nprePaths:\n" + printPaths(prePaths, false) + "\n";
                                        //             if (realTest) {
                                        //                 for (Vector<Set<Integer>> prePath : prePaths) {
                                        //                     if (threadInterrupt("", false)) return;
                                        //
                                        //                     Enumerator preEnum = new Enumerator(prePath);
                                        //                     Enumerator pumpEnum = new Enumerator(pumpPath);
                                        //                     if (dynamicValidate(preEnum, pumpEnum, VulType.POA)) return;
                                        //                 }
                                        //             }
                                        //         }
                                        //     }
                                        // }
                                    }
                                }
                            // }
                            ThreadsNum[0]--;
                        }
                    });
                }
            }


            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            while(!getResult[0] && !Thread.currentThread().isInterrupted() && ThreadsNum[0] != 0) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    // e.printStackTrace();
                    System.out.println("线程请求中断...1");
                    return;
                }
            }

            // 停止executorService中的所有线程，并销毁executorService
            executorService.shutdownNow();

            System.out.println("[*] POA finished");
        }

        if (threadInterrupt("\nTraversing paths time out\n", true)) return;

        if (SLQ) {
            final boolean[] getResult = {false};
            ExecutorService executorService = Executors.newCachedThreadPool();

            // Collections.sort((countingNodes), new Comparator<LeafNode>() {
            //     @Override
            //     public int compare(LeafNode o1, LeafNode o2) {
            //         // return id2childNodes.get(o1.id).size() - id2childNodes.get(o2.id).size();
            //         return o2.id - o1.id;
            //     }
            // });

            for (LeafNode node : countingNodes) {
                if (threadInterrupt("\nTraversing paths time out\n", true)) return;
                executorService.execute(new Runnable() {
                    @Override
                    public void run() {
                        ThreadsNum[0]++;
                        // synchronized (countingPrePaths) {
                            // System.out.println("----------------------------------------------------------\nnode regex: " + node.SelfRegex + "\npumpPaths:\n" + printPaths(node.getRealPaths(), false) + "\n");
                            Enumerator preEnum = new Enumerator(new Vector<>());
                            if (debugStuck) System.out.println("node: " + node.id + ",regex:" + node.SelfRegex);
                            if (threadInterrupt("\nTraversing paths time out\n", true)) return;

                            // 如果cmax小于100或后缀可空，则不需要检查
                            if (((LoopNode) node).cmax < 100 || !neverhaveEmptySuffix(node)) return;
                            if (debugStuck) System.out.println("run node: " + node.id + ",regex:" + node.SelfRegex);
                            // SLQ1：counting开头可空，测试""+y*n+"\b\n\b"
                            if (debugPath)
                                attackMsg += "----------------------------------------------------------\nnode regex: " + node.SelfRegex + "\nprePaths:\n" + printPaths(countingPrePaths.get(node), false) + "\npumpPaths:\n" + printPaths(node.getRealPaths(), false) + "\n";
                            System.out.println("\nnode regex: " + node.SelfRegex + "\n");

                            if (haveEmptyBeginning(node)) {
                                if (debugPath)
                                    attackMsg += "SLQ1:\npump paths\n" + printPaths(node.getRealPaths(), false) + "\n";
                                if (realTest) {
                                    synchronized (countingPrePaths) {
                                        if (countingPrePaths.get(node) == null) {
                                            Vector<Path> prePaths = generatePrePath(node);
                                            Collections.sort((prePaths), new Comparator<Path>() {
                                                @Override
                                                public int compare(Path o1, Path o2) {
                                                    return o1.getRealCharSize() - o2.getRealCharSize();
                                                }
                                            });
                                            Vector<Vector<Set<Integer>>> realPrePaths = new Vector<>();
                                            for (Path path : prePaths) {
                                                realPrePaths.addAll(path.getRealPaths(false));
                                            }
                                            countingPrePaths.put(node, realPrePaths);
                                        }
                                    }
                                    if (countingPrePaths.get(node).size() == 0) {
                                        for (Vector<Set<Integer>> pumpPath : node.getRealPaths()) {
                                            if (Thread.currentThread().isInterrupted()) {
                                                System.out.println("线程请求中断...4");
                                                return;
                                            }
                                            Enumerator pumpEnum = new Enumerator(pumpPath);
                                            if (dynamicValidate(preEnum, pumpEnum, VulType.SLQ)) {
                                                getResult[0] = true;
                                                ThreadsNum[0]--;
                                                return;
                                            }
                                        }
                                    }
                                    else {
                                        for (Vector<Set<Integer>> prePath : countingPrePaths.get(node)) {
                                            if (Thread.currentThread().isInterrupted()) {
                                                System.out.println("线程请求中断...5");
                                                return;
                                            }
                                            preEnum = new Enumerator(prePath);
                                            for (Vector<Set<Integer>> pumpPath : node.getRealPaths()) {
                                                if (Thread.currentThread().isInterrupted()) {
                                                    System.out.println("线程请求中断...6");
                                                    return;
                                                }
                                                Enumerator pumpEnum = new Enumerator(pumpPath);
                                                if (dynamicValidate(preEnum, pumpEnum, VulType.SLQ)) {
                                                    getResult[0] = true;
                                                    ThreadsNum[0]--;
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            else {
                                synchronized (countingPrePaths) {
                                    if (countingPrePaths.get(node) == null) {
                                        Vector<Path> prePaths = generatePrePath(node);
                                        Collections.sort((prePaths), new Comparator<Path>() {
                                            @Override
                                            public int compare(Path o1, Path o2) {
                                                return o1.getRealCharSize() - o2.getRealCharSize();
                                            }
                                        });
                                        Vector<Vector<Set<Integer>>> realPrePaths = new Vector<>();
                                        for (Path path : prePaths) {
                                            realPrePaths.addAll(path.getRealPaths(false));
                                        }
                                        countingPrePaths.put(node, realPrePaths);
                                    }
                                }
                                // SLQ2：counting开头不可空，判断前缀是否是中缀的子串，如果有重叠，测试""+(中缀&前缀）*n+"\b\n\b"
                                for (Vector<Set<Integer>> pumpPath : node.getRealPaths()) {
                                    for (Vector<Set<Integer>> prePath : countingPrePaths.get(node)) {
                                        if (threadInterrupt("\nTraversing paths time out\n", true)) return;

                                        if (prePath.size() == 0) continue;
                                        // if (isPath2InPath1(pumpPath, prePath)) {
                                        //     Enumerator pumpEnum = new Enumerator(pumpPath);
                                        //     System.out.println("pre:");
                                        //     System.out.println(printPath(prePath));
                                        //     System.out.println("pump:");
                                        //     System.out.println(printPath(pumpPath));
                                        //     if (dynamicValidate(preEnum, pumpEnum, VulType.SLQ)) return;
                                        //     System.out.println("\n----------\n");
                                        // }

                                        Vector<Vector<Set<Integer>>> pumpPaths = new Vector<>();
                                        if (isPath2InPath1_returnPaths(pumpPath, prePath, pumpPaths)) {
                                            if (debugPath)
                                                attackMsg += "SLQ2" + "\n" + "pre:" + "\n" + printPath(prePath, false) + "\n" + "pump:" + "\n" + printPath(pumpPath, false) + "\n" + "pumpPaths:" + "\n" + printPaths(pumpPaths, false) + "\n";
                                            if (realTest) {
                                                for (Vector<Set<Integer>> pumpPath_ : pumpPaths) {
                                                    if (Thread.currentThread().isInterrupted()) {
                                                        System.out.println("线程请求中断...7");
                                                        return;
                                                    }
                                                    Enumerator pumpEnum = new Enumerator(pumpPath_);
                                                    // System.out.println("pre:");
                                                    // System.out.println(printPath(prePath));
                                                    // System.out.println("pump:");
                                                    // System.out.println(printPath(pumpPath));
                                                    if (dynamicValidate(preEnum, pumpEnum, VulType.SLQ)) {
                                                        getResult[0] = true;
                                                        ThreadsNum[0]--;
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        // }
                        ThreadsNum[0]--;
                    }
                });
            }


            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            while(!getResult[0] && !Thread.currentThread().isInterrupted() && ThreadsNum[0] != 0) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    // e.printStackTrace();
                    System.out.println("线程请求中断...1");
                    return;
                }
            }

            // 停止executorService中的所有线程，并销毁executorService
            executorService.shutdownNow();

            System.out.println("[*] SLQ finished");
        }

        if (debugPath) {
            try {
                attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            try {
                BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                writer.write(id + "," + attackMsg + "\n");
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    void generateStandardCharSets(){
        //获取特定类别的节点set
        if(Dot == null) Dot = getNodeCharSet((Pattern.CharProperty) DotP.root.next);
        // Bound = getNodeCharSet((Pattern.CharProperty) BoundP.root.next);
        if(Space == null) Space = getNodeCharSet((Pattern.CharProperty) SpaceP.root.next);
        if(SpaceFull == null) SpaceFull = new HashSet<Integer>(){{
            addAll(Space);
            if (SpaceFullSet) {
                add(0x00a0);
                add(0x1680);
                for (int i = 0x2000; i <= 0x200a; i++) {
                    add(i);
                }
                add(0x2028);
                add(0x2029);
                add(0x202f);
                add(0x205f);
                add(0x3000);
                add(0xfeff);
            }
        }};
        if(noneSpace == null) noneSpace = getNodeCharSet((Pattern.CharProperty) noneSpaceP.root.next);
        if(word == null) word = getNodeCharSet((Pattern.CharProperty) wordP.root.next);
        if(All == null) All = getNodeCharSet((Pattern.CharProperty) AllP.root.next);
        if(noneWord == null) noneWord = getNodeCharSet((Pattern.CharProperty) noneWordP.root.next);

        generateRawCharSet((Pattern.CharProperty) DefaultSmallCharSetP.root.next, false);
    }

    boolean threadInterrupt(String debugMsg, boolean debug) {
        if(Thread.currentThread().isInterrupted()){
            System.out.println("线程请求中断...2");
            if (debugPath && debug) {
                try {
                    attackMsg += debugMsg;
                    attackMsg = (endTime - startTime) + "," + Base64.getEncoder().encodeToString(attackMsg.getBytes("utf-8"));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
                try {
                    BufferedWriter writer = new BufferedWriter(new FileWriter("path-result.txt", true));
                    writer.write(id + "," + attackMsg + "\n");
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return true;
        }
        return false;
    }

    /**
     * 判断两个Node谁前谁后，并且返回中间路径
     * @param node1
     * @param node2
     * @return 如果能分出前后（最小父节点是ConnectNode），返回中间路径和前节点；如果是Branch，返回null，表示跳过不测
     */
    Pair<Vector<Vector<Set<Integer>>>, LeafNode> getMidAndFrontNode(LeafNode node1, LeafNode node2) {
        Vector<Vector<Set<Integer>>> midPaths = new Vector<>();
        // 向上遍历，找到最小公共父节点
        LeafNode tmp = node1;
        LeafNode father = tmp;
        while (!id2childNodes.get(father.id).contains(node2.id)  && !Thread.currentThread().isInterrupted()) {
            father = tmp.father;
            tmp = father;
        }

        if (threadInterrupt("getMidAndFrontNode", false)) return null;

        if (father instanceof ConnectNode) {
            Vector<Path> prefixPaths = new Vector<>();
            Vector<Path> suffixPaths = new Vector<>();
            LeafNode front = null, back = null;
            if (((ConnectNode) father).comeFromLeft(node1) && ((ConnectNode) father).comeFromRight(node2)) {
                // 说明node1在前，node2在后，node1求后缀，node2求前缀，在最小父节点相遇组合就是中间路径
                front = node1;
                back = node2;
            }
            else if (((ConnectNode) father).comeFromLeft(node2) && ((ConnectNode) father).comeFromRight(node1)) {
                // 说明node2在前，node1在后，node2求后缀，node1求前缀，在最小父节点相遇组合就是中间路径
                front = node2;
                back = node1;
            }

            tmp = front;
            LeafNode tmpfather = tmp.father;
            while (tmpfather != father && !Thread.currentThread().isInterrupted()) {
                if (tmpfather instanceof ConnectNode && ((ConnectNode) tmpfather).comeFromRight(tmp)) {
                    prefixPaths = splicePath(((ConnectNode) tmpfather).returnTrueLeftPaths(), prefixPaths);
                }
                tmp = tmpfather;
                tmpfather = tmp.father;
            }

            tmp = back;
            tmpfather = tmp.father;
            while (tmpfather != father && !Thread.currentThread().isInterrupted()) {
                if (tmpfather instanceof ConnectNode && ((ConnectNode) tmpfather).comeFromRight(tmp)) {
                    suffixPaths = splicePath(((ConnectNode) tmpfather).returnTrueLeftPaths(), suffixPaths);
                }
                tmp = tmpfather;
                tmpfather = tmp.father;
            }

            Vector<Path> tmpMidPaths = splicePath(prefixPaths, suffixPaths);

            Collections.sort((tmpMidPaths), new Comparator<Path>() {
                @Override
                public int compare(Path o1, Path o2) {
                    return o1.getRealCharSize() - o2.getRealCharSize();
                }
            });

            for (Path path : tmpMidPaths) {
                midPaths.addAll(path.getRealPaths(true));
            }

            return new Pair<>(midPaths, front);
        }
        else if (father instanceof BranchNode) {
            // 如果最小公共父节点是分支的话，说明之间不夹着东西，视作相邻，前缀都一样，随便返回一个即可
            // return new Pair<>(midPaths, node1);

            // 如果最小公公节点时分支的话，不可能构成poa，跳过
            return null;
        }
        else {
            throw new Error("father is not ConnectNode or BranchNode");
        }
    }

    boolean isNode1ChildOfNode2(LeafNode node1, LeafNode node2) {
        if (id2childNodes.get(node2.id).contains(node1.id)) return true;
        return false;
    }

    boolean isPath2InPath1(Vector<Set<Integer>> path1, Vector<Set<Integer>> path2) {
        // 默认path1是大串，path2是小串，如果path1.path.size() < path2.path.size()，return false
        if (path1.size() < path2.size()) {
            return false;
        } else {
            // Vector<oldPath> result = new Vector<>();
            // 对path1.path滑动窗口，从开始到path1.path.size() - path2.path.size()，每次滑动一位
            for (int i = 0; i < path1.size() - path2.size() + 1; i++) {
                // 对每一个滑动窗口，比较每一个节点的字符集
                Vector<Set<Integer>> charSet1 = new Vector<>();
                boolean path2InPath1 = true;
                for (int j = 0; j < path2.size(); j++) {
                    Set<Integer> tmpCharSet = new HashSet<>();
                    tmpCharSet.addAll(path1.get(i + j));
                    tmpCharSet.retainAll(path2.get(j));
                    if (tmpCharSet.size() == 0) {
                        path2InPath1 = false;
                        break;
                    } else {
                        charSet1.add(tmpCharSet);
                    }
                }
                if (path2InPath1) return true;
            }
        }
        return false;
    }

    boolean isPath2InPath1_returnPaths(Vector<Set<Integer>> path1, Vector<Set<Integer>> path2, Vector<Vector<Set<Integer>>> result) {
        // 默认path1是大串，path2是小串，如果path1.path.size() < path2.path.size()，return false
        if (path1.size() < path2.size()) {
            return false;
        } else {
            // Vector<oldPath> result = new Vector<>();
            // 对path1.path滑动窗口，从开始到path1.path.size() - path2.path.size()，每次滑动一位
            for (int i = 0; i < path1.size() - path2.size() + 1 && !Thread.currentThread().isInterrupted(); i++) {
                // 对每一个滑动窗口，比较每一个节点的字符集
                Vector<Set<Integer>> charSet1 = new Vector<>();
                boolean path2InPath1 = true;
                for (int j = 0; j < path2.size() && !Thread.currentThread().isInterrupted(); j++) {
                    Set<Integer> tmpCharSet = new HashSet<>();
                    tmpCharSet.addAll(path1.get(i + j));
                    tmpCharSet.retainAll(path2.get(j));
                    if (tmpCharSet.size() == 0) {
                        path2InPath1 = false;
                        break;
                    } else {
                        charSet1.add(tmpCharSet);
                    }
                }

                // 如果path2在path1中，视作path1_1 + path1_2 + path1_3中的path1_2与path2有重叠
                // 把path1_1 + path1_2 & path2 + path1_3放入result
                if (path2InPath1) {
                    boolean rawPathHaveNoneSet = false;
                    // charSet1是path1_2 & path2，这一步为在其后添加path1_3
                    for (int j = i + path2.size(); j < path1.size() && !Thread.currentThread().isInterrupted(); j++) {
                        if (path1.get(j).size()==0) {
                            rawPathHaveNoneSet = true;
                            break;
                        }
                        charSet1.add(new HashSet<>(path1.get(j)));
                    }
                    // 构造tmpResult = path1_1
                    Vector<Set<Integer>> tmpResult = new Vector<Set<Integer>>();
                    for (int j = 0; j < i && !Thread.currentThread().isInterrupted(); j++) {
                        if (path1.get(j).size()==0) {
                            rawPathHaveNoneSet = true;
                            break;
                        }
                        tmpResult.add(new HashSet<>(path1.get(j)));
                    }
                    if (rawPathHaveNoneSet) continue;
                        // 使tmpResult = path1_1 + path1_2 & path2 + path1_3
                    else {
                        tmpResult.addAll(charSet1);
                        result.add(tmpResult);
                    }
                }
            }

            if (result.size() > 0) return true;
        }
        return false;
    }

    private boolean haveEmptyBeginning(LeafNode node) {
        while (node != this.root && !Thread.currentThread().isInterrupted()) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromRight(node)) {
                Vector<Path> prePaths = ((ConnectNode) father).returnTrueLeftPaths();
                if (prePaths.size() != 0 && prePaths.get(0).getRealCharSize() != 0 ) return false;
                if (((ConnectNode) father).beginInLeftPath()) return false;
            }
            node = father;
        }
        return true;
    }

    private boolean neverhaveEmptySuffix(LeafNode node) {
        boolean result = false;
        while (node != this.root && !Thread.currentThread().isInterrupted()) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromLeft(node)) {
                Vector<Path> suffixPaths = ((ConnectNode) father).returnTrueRightPaths();
                if (suffixPaths.size() != 0 && suffixPaths.get(0).getRealCharSize() != 0 ) result = true;
                if (((ConnectNode) father).endInRight()) result = true;
            }
            else if (father instanceof LoopNode && ((LoopNode) father).cmin == 0) {
                result = false;
            }
            node = father;
        }
        return result;
    }

    enum VulType {
        OneCounting, POA, SLQ
    }

    /**
     * 对给定的前缀和中缀进行枚举并验证是否具有攻击性
     * @param preEnum 前缀枚举类
     * @param pumpEnum 中缀枚举类
     * @param type 检测的是OneCounting、POA、SLQ中哪类漏洞
     * @return 是否具有攻击性
     */
    private boolean dynamicValidate(Enumerator preEnum, Enumerator pumpEnum, VulType type) {
        int pumpMaxLength = 50;
        if (type == VulType.OneCounting) {
            pumpMaxLength = 50;
        } else if (type == VulType.POA) {
            pumpMaxLength = 30000;
        } else if (type == VulType.SLQ) {
            pumpMaxLength = 30000;
        }

        // if (this.regex.equals("(\\s)*(int|void|float|char|double|string)((\\s)|(\\*))*(\\&?)(\\s)+([a-z])([a-z0-9])*(\\s)*(\\()(\\s)*((int|void|float|char|double|string)((\\s)|(\\*))*(\\&?)(\\s)+([a-z])([a-z0-9])*((\\s)*[,](\\s)*(int|void|float|char|double|string)((\\s)|(\\*))*(\\&?)(\\s)+([a-z])([a-z0-9])*)*)?(\\s)*(\\))(\\s)*;")) {
        //     try {
        //         Thread.sleep(10000);
        //     } catch (InterruptedException e) {
        //         e.printStackTrace();
        //     }
        // }

        // 如果前缀可空的话，前缀固定为""，只枚举后缀
        if (preEnum.Empty()) {
            while (pumpEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                String pump = pumpEnum.next();
                double matchingStepCnt = 0;
                if (debugStep) System.out.println("pump:" + pump);
                try {
                    if (type == VulType.SLQ)
                        matchingStepCnt = testPattern4Search.getMatchingStepCnt("", pump, "\n\b\n", pumpMaxLength, 1000000);
                    else matchingStepCnt = testPattern.getMatchingStepCnt("", pump, "\n\b\n", pumpMaxLength, 100000);
                } catch (StackOverflowError e) {
                    // e.printStackTrace();
                    System.out.println("StackOverflowError");
                    matchingStepCnt = 1000001;
                }
                if (debugStep) System.out.println(matchingStepCnt);
                if (matchingStepCnt > (SLQ?1e6:1e5)) {
                    try {
                        synchronized(attackMsg) {
                            String tmp_attackMsg = "";
                            // type
                            tmp_attackMsg += type;
                            tmp_attackMsg += ",";
                            // pre
                            tmp_attackMsg += Base64.getEncoder().encodeToString("".getBytes("utf-8"));
                            tmp_attackMsg += ",";
                            // pump
                            tmp_attackMsg += Base64.getEncoder().encodeToString(pump.getBytes("utf-8"));
                            tmp_attackMsg += ",";
                            // suffix
                            tmp_attackMsg += Base64.getEncoder().encodeToString("\\n\\b\\n".getBytes("utf-8"));
                            attackMsg = tmp_attackMsg;
                        }
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    System.out.println("MatchSteps: " + matchingStepCnt);
                    // System.out.println("\nprefix:\n" + "pump:" + pump + "\nsuffix:\\n\\b\\n");
                    attackable = true;
                    // attackMsg = type + "\nprefix:\n" + "pump:" + pump + "\nsuffix:\\n\\b\\n";
                    return true;
                }
                // System.out.println("");
            }
        }
        // 如果前缀不可空的话，前缀和中缀组合枚举
        else {
            while (preEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                String pre = preEnum.next();
                while (pumpEnum.hasNext() && !Thread.currentThread().isInterrupted()) {
                    String pump = pumpEnum.next();
                    double matchingStepCnt;
                    if (debugStep) System.out.println("pre:" + pre + "\npump:" + pump);
                    try {
                        if (type == VulType.SLQ) matchingStepCnt = testPattern4Search.getMatchingStepCnt(pre, pump, "\n\b\n", pumpMaxLength, 1000000);
                        else matchingStepCnt = testPattern.getMatchingStepCnt(pre, pump, "\n\b\n", pumpMaxLength, 100000);
                    } catch (StackOverflowError e) {
                        // e.printStackTrace();
                        System.out.println("StackOverflowError");
                        matchingStepCnt = 1000001;
                    }
                    if (debugStep) System.out.println(matchingStepCnt);
                    if (matchingStepCnt > (SLQ?1e6:1e5)) {
                        try {
                            synchronized(attackMsg) {
                                String tmp_attackMsg = "";
                                // type
                                tmp_attackMsg += type;
                                tmp_attackMsg += ",";
                                // pre
                                tmp_attackMsg += Base64.getEncoder().encodeToString(pre.getBytes("utf-8"));
                                tmp_attackMsg += ",";
                                // pump
                                tmp_attackMsg += Base64.getEncoder().encodeToString(pump.getBytes("utf-8"));
                                tmp_attackMsg += ",";
                                // suffix
                                tmp_attackMsg += Base64.getEncoder().encodeToString("\\n\\b\\n".getBytes("utf-8"));
                                attackMsg = tmp_attackMsg;
                            }
                        } catch (UnsupportedEncodingException e) {
                            e.printStackTrace();
                        }
                        System.out.println("MatchSteps: " + matchingStepCnt);
                        // System.out.println("\nprefix:" + pre + "\n" + "pump:" + pump + "\nsuffix:\\n\\b\\n");
                        attackable = true;
                        // attackMsg = type + "\nprefix:" + pre + "\n" + "pump:" + pump + "\nsuffix:\\n\\b\\n";
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * 当两条路径具有一条完全重合的路径时，返回重合路径
     * @param path1 路径1
     * @param path2 路径2
     * @return 路径1和2的重合路径
     */
    Vector<Set<Integer>> getPathCompletelyOverLap(Vector<Set<Integer>> path1, Vector<Set<Integer>> path2) {
        Vector<Set<Integer>> result = new Vector<>();
        // 如果两条path的长度不同，则不可能有完全重叠
        if (path1.size() != path2.size()) {
            return result;
        }
        else {
            // 如果两个路径的长度相同，则需要比较每一个节点的字符集
            Vector<Set<Integer>> charSet1 = new Vector<>();
            for (int i = 0; i < path1.size() && !Thread.currentThread().isInterrupted(); i++) {
                Set<Integer> tmpCharSet = new HashSet<>();
                tmpCharSet.addAll(path1.get(i));
                tmpCharSet.retainAll(path2.get(i));
                if (tmpCharSet.size() == 0) {
                    return result;
                } else {
                    charSet1.add(tmpCharSet);
                }
            }
            return charSet1;
        }
    }

    /**
     * 路径的枚举类，用来从一条路径中依次枚举出所有字符串
     */
    private class Enumerator {
        Vector<Vector<Integer>> path; // 把Vector<Set<Integer>>转换成Vector<Vector<Integer>>存储
        Vector<Vector<Integer>> pathRand;
        Vector<Integer> indexs; // 路径中的每一位所遍历到的序号
        Random rand;
        int times; // 当前路径中已经遍历的次数

        public Enumerator(Vector<Set<Integer>> path) {
            this.indexs = new Vector<>();
            this.path = new Vector<>();
            for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                this.path.add(new Vector<>(path.get(i)));
                this.indexs.add(0);
            }
            if (!haveAdvancedFeatures) {
                this.rand = new Random(System.currentTimeMillis());
                pathRand = new Vector<>();
                for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                    pathRand.add(new Vector<>(path.get(i)));
                }
            }
            this.times = 0;
        }

        public String next() {
            times++;
            if (haveAdvancedFeatures) return nextAdvanced();
            else return nextNoAdvanced();
        }

        private String nextAdvanced() {
            String sb = "";
            for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                int tmp = path.get(i).get(indexs.get(i));
                sb += (char) tmp;
            }

            for (int i = indexs.size() - 1; i >= 0 && !Thread.currentThread().isInterrupted(); i--) {
                // 如果这一位的index遍历到头，则重置这一位，进入下一轮循环让下一位进位
                if (indexs.get(i) == path.get(i).size()) {
                    indexs.set(i, 0);
                    continue;
                } else {
                    // 如果这一位的index还没有遍历到头，让这一位的index加1
                    indexs.set(i, indexs.get(i) + 1);
                    // 如果这一位经过加1遍历到头的话，重置这一位，给前一位加1
                    for (int j = i; j > 0 && indexs.get(j) == path.get(j).size() && !Thread.currentThread().isInterrupted(); j--) {
                        indexs.set(j - 1, indexs.get(j - 1) + 1);
                        indexs.set(j, 0);
                    }
                    break;
                }
            }
            return sb;
        }

        private String nextNoAdvanced() {
            // 随机给出path的组合
            String sb = "";
            for (int i = 0; i < path.size() && !Thread.currentThread().isInterrupted(); i++) {
                sb += getRandChar(i);
            }
            return sb;
        }

        private char getRandChar(int i) {
            if (pathRand.get(i).size() == 0) {
                pathRand.set(i, new Vector<>(path.get(i)));
            }
            int randIndex = rand.nextInt(pathRand.get(i).size());
            int randChar = pathRand.get(i).get(randIndex);
            pathRand.get(i).remove(randIndex);
            return (char) randChar;
        }

        public boolean hasNext() {
            if (haveAdvancedFeatures) {
                if (this.indexs.size() == 0) {
                    return false;
                }
                int t1 = this.indexs.get(0);
                int t2 = this.path.get(0).size();
                boolean result = t1 < t2;
                return result;
            }
            else {
                return this.times < 1;
            }
        }

        public boolean Empty() {
            return this.indexs.size() == 0;
        }

        public void reset() {
            for (int i = 0; i < this.indexs.size() && !Thread.currentThread().isInterrupted(); i++) {
                this.indexs.set(i, 0);
            }
        }
    }
    //
    // private LeafNode rightNextLeaf(LeafNode node) {
    //     LeafNode father = node.father;
    //     if(father instanceof LinkNode) {
    //         if(father)
    //     }
    //     else {
    //         throw new RuntimeException("rightNextLeaf error:father is not a LinkNode");
    //     }
    // }
    //
    // private LeafNode getRightestLeaf(LeafNode node) {
    //     if (node instanceof LinkNode) {
    //         if (node instanceof ConnectNode) {
    //
    //         }
    //         else if (node instanceof BranchNode) {
    //
    //         }
    //         else if (node instanceof LoopNode) {
    //
    //         }
    //         else if (node instanceof LookaroundNode) {
    //
    //         }
    //     }
    //     else {
    //         return node;
    //     }
    // }

    // 普通的节点类，默认不可以向下连接其他节点，只能出现在叶子上
    private class LeafNode {
        Set<Integer> groupNums;
        LeafNode father;
        Vector<Path> paths;
        Vector<Vector<Set<Integer>>> realPaths;
        boolean realPathsGenerated = false;
        Pattern.Node actualNode;
        boolean beginInPath = false;
        boolean endInPath = false;
        int id;
        String SelfRegex = "";
        boolean pathGenerated = false;
        Set<Integer> first;
        Set<Integer> last;
        boolean couldBeEmpty = false;

        LeafNode (Set<Integer> groupNums, Pattern.Node actualNode) {
            this.groupNums = new HashSet<Integer>(groupNums);
            this.paths = new Vector<>();
            this.actualNode = actualNode;
            this.first = new HashSet<>();
            this.last = new HashSet<>();
            this.realPaths = new Vector<>();
        }

        LeafNode copy(LeafNode father, Set<Integer> groupNums) {
            LeafNode result = new LeafNode(groupNums, actualNode);
            // result.paths = new Vector<>(this.paths);
            result.father = father;
            if (this.pathGenerated) {
                result.paths = new Vector<>(this.paths);
                result.pathGenerated = true;
            }
            return result;
        }

        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "<br>"
                    + (debug ? "groupNums:" + groupNums.toString() + "<br>" : "")
                    + (debug ? "id:" + this.id + "<br>" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex.replace("\"", "\\x22") + "<br>" : "")
                    + (debug&&debugFirstAndLast ? "first:{" + printSet(first, true) + "}<br>" : "")
                    + (debug&&debugFirstAndLast ? "last:{" + printSet(last, true) + "}<br>" : "")
                    +printPaths(this.getRealPaths(), true)+"\"]");
        }

        void generateSelfRegex() {
            if (this.actualNode == null) return;

            if (this.actualNode instanceof Pattern.CharProperty) {
                Pattern.CharProperty cp = (Pattern.CharProperty) this.actualNode;
                if (cp.charSet.size() != 0) {
                    if (setsEquals(cp.charSet, Dot)) this.SelfRegex += ".";
                        // else if (setsEquals(cp.charSet, Bound)) this.SelfRegex += "\\b";
                    else if (setsEquals(cp.charSet, SpaceFull)) this.SelfRegex += "\\s";
                    else if (setsEquals(cp.charSet, noneSpace)) this.SelfRegex += "\\S";
                    else if (setsEquals(cp.charSet, All)) this.SelfRegex += "[\\s\\S]";
                    else if (setsEquals(cp.charSet, word)) this.SelfRegex += "\\w";
                    else if (setsEquals(cp.charSet, noneWord)) this.SelfRegex += "\\W";
                    else {
                        this.SelfRegex += "[";
                        this.SelfRegex += cp.selfRegex;
                        this.SelfRegex += "]";
                    }
                }
            }
            else if (this.actualNode instanceof Pattern.SliceNode) {
                Pattern.SliceNode sn = (Pattern.SliceNode) this.actualNode;
                for (int i : sn.buffer) {
                    this.SelfRegex += int2String(i);
                }
            }
            else if (this.actualNode instanceof Pattern.BnM) {
                Pattern.BnM bn = (Pattern.BnM) this.actualNode;
                for (int i : bn.buffer) {
                    this.SelfRegex += int2String(i);
                }
            }
        }

        Vector<Path> getPaths() {
            if (!this.pathGenerated) {
                generateAllPath(this);
                this.pathGenerated = true;
            }
            return this.paths;
        }

        synchronized Vector<Vector<Set<Integer>>> getRealPaths(){
            if (!this.pathGenerated) {
                generateAllPath(this);
                this.pathGenerated = true;
            }
            if (!this.realPathsGenerated) {
                for (Path path : this.paths) {
                    realPaths.addAll(path.getRealPaths(true));
                }
                realPathsGenerated = true;
            }
            return this.realPaths;
        }

        public void generatePaths() {
            if (pathGenerated) return;
            if (this.actualNode instanceof Pattern.CharProperty){
                // Vector<Set<Integer>> tmpPath = new Vector<>();
                Path tmpPath = new Path();
                if (((Pattern.CharProperty) this.actualNode).charSet.size() > 0) {
                    PathNode pn = new PathNode(((Pattern.CharProperty) this.actualNode).charSet);
                    tmpPath.add(pn);
                }
                this.paths.add(tmpPath);
                this.pathGenerated = true;
            }
            else if (this.actualNode instanceof Pattern.SliceNode){
                // Vector<Set<Integer>> tmpPath = new Vector<>();
                Path tmpPath = new Path();
                for (int i : ((Pattern.SliceNode) this.actualNode).buffer) {
                    Set<Integer> tmpCharSet = new HashSet<>();
                    tmpCharSet.add(i);
                    PathNode pn = new PathNode(tmpCharSet);
                    // tmpPath.add(tmpCharSet);
                    tmpPath.add(pn);
                }
                this.paths.add(tmpPath);
                this.pathGenerated = true;
            }
            else if (this.actualNode instanceof Pattern.BnM) {
                // Vector<Set<Integer>> tmpPath = new Vector<>();
                Path tmpPath = new Path();
                for (int i : ((Pattern.BnM) this.actualNode).buffer) {
                    Set<Integer> tmpCharSet = new HashSet<>();
                    tmpCharSet.add(i);
                    // tmpPath.add(tmpCharSet);
                    PathNode pn = new PathNode(tmpCharSet);
                    tmpPath.add(pn);
                }
                this.paths.add(tmpPath);
                this.pathGenerated = true;
            }
        }

        public void generateFistAndLast(){
            if (this.paths.size() == 0) {
                this.couldBeEmpty = true;
                return;
            }
            if (this.actualNode instanceof Pattern.CharProperty){
                this.first = ((Pattern.CharProperty) this.actualNode).charSet;
                this.last = ((Pattern.CharProperty) this.actualNode).charSet;
            }
            else if (this.actualNode instanceof Pattern.SliceNode || this.actualNode instanceof Pattern.BnM){
                this.first.addAll(this.paths.get(0).getRealPaths(false).get(0).get(0));
                this.last.addAll(this.paths.get(0).getRealPaths(false).get(0).get(this.paths.get(0).getRealPaths(false).get(0).size() - 1));
            }
        }

    }

    private String int2String(int i) {
        return int2String(i, false);
    }

    private String int2String(int i, boolean mermaid) {

        switch (i) {
            case 7:
                return "\\a";
            case 8:
                return "\\b";
            case 9:
                return "\\t";
            case 10:
                return mermaid ? "\\n" : "\\n";
            case 11:
                return "\\v";
            case 12:
                return "\\f";
            case 13:
                return "\\r";
            case 92:
                return "\\\\";
            case 39:
                return "\\'";
            case 34:
                return mermaid ? "''" : "\\\"";
            case 72:
                return "\\(";
            case 123:
                return "\\{";
            case 91:
                return "\\[";
            case 46:
                return "\\.";
            case 124:
                return "\\|";
            case 42:
                return "\\*";
            case 63:
                return "\\?";
            case 43:
                return "\\+";
            default:
                return (char) i + "";
        }
    }

    // 能够连接其他节点的类拓展自LinkNode
    private abstract class LinkNode extends LeafNode {
        LinkNode(Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
        }

        abstract void replaceChild(LeafNode oldNode, LeafNode newNode);
    }

    // 连接结构
    private class ConnectNode extends LinkNode {
        LeafNode left;
        LeafNode right;
        Vector<Path> leftPaths;
        Vector<Path> rightPaths;

        ConnectNode (LeafNode left, LeafNode right, Set<Integer> groupNums) {
            super(groupNums, null);
            this.left = left;
            this.right = right;

            if (left != null) left.father = this;
            if (right != null) right.father = this;
        }

        /**
         * 根据左右子树路径生成本节点的路径
         */
        @Override
        public void generatePaths() {
            if (pathGenerated) return;
            // assignId2Node(this);
            leftPaths = new Vector<>();
            rightPaths = new Vector<>();

            if (left != null) {
                if (!(left instanceof LookaroundNode)) {
                    leftPaths.addAll(left.getPaths());
                    if (left.beginInPath) this.beginInPath = true;
                    if (left.endInPath) this.endInPath = true;
                }
                else {
                    Path tmpPath = new Path();
                    PathNode pn = new PathNode(left.getPaths(), ((LookaroundNode) left).type);
                    tmpPath.add(pn);
                    leftPaths.add(tmpPath);
                }
            }
            if (right != null) {
                if (!(right instanceof LookaroundNode)) {
                    rightPaths.addAll(right.getPaths());
                    if (right.beginInPath) this.beginInPath = true;
                    if (right.endInPath) this.endInPath = true;
                }
                else {
                    Path tmpPath = new Path();
                    PathNode pn = new PathNode(right.getPaths(), ((LookaroundNode) right).type);
                    tmpPath.add(pn);
                    rightPaths.add(tmpPath);
                }
            }

            if (leftPaths.size() == 0) {
                this.paths.addAll(rightPaths);
            }
            else if (rightPaths.size() == 0) {
                this.paths.addAll(leftPaths);
            }
            else {
                for (Path leftPath : leftPaths) {
                    for (Path rightPath : rightPaths) {
                        if (threadInterrupt("", false)) return;

                        // if (leftPath.size() + rightPath.size() > maxLength) {
                        if (leftPath.getRealCharSize() + rightPath.getRealCharSize() > maxLength) {
                            continue;
                        }
                        // Vector<Set<Integer>> newPath = new Vector<>();
                        Path newPath = new Path();
                        newPath.addAll(leftPath);
                        newPath.addAll(rightPath);
                        this.paths.add(newPath);
                    }
                }
            }

            if (threadInterrupt("", false)) return;


            Collections.sort((this.paths), new Comparator<Path>() {
                @Override
                public int compare(Path o1, Path o2) {
                    return o1.getRealCharSize() - o2.getRealCharSize();
                }
            });
        }

        @Override
        void generateSelfRegex(){
            if(left != null)
                this.SelfRegex += left.SelfRegex;
            if(right != null)
                this.SelfRegex += right.SelfRegex;
        }

        @Override
        public void generateFistAndLast(){
            boolean leftCouldBeEmpty = left == null || left instanceof LookaroundNode || left.couldBeEmpty;
            boolean rightCouldBeEmpty = right == null || right instanceof LookaroundNode || right.couldBeEmpty;

            if (left != null) {
                this.first.addAll(left.first);
            }
            if (right != null) {
                this.last.addAll(right.last);
            }

            if (leftCouldBeEmpty && rightCouldBeEmpty) {
                this.couldBeEmpty = true;
            }
            else if (leftCouldBeEmpty && right != null) {
                this.first.addAll(right.first);
            }
            else if (rightCouldBeEmpty && left != null) {
                this.last.addAll(left.last);
            }
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            if (left == oldNode) {
                left = newNode;
                if (newNode != null) newNode.father = this;
            }
            else if (right == oldNode) {
                right = newNode;
                if (newNode != null) newNode.father = this;
            }
        }

        boolean comeFromLeft(LeafNode node) {
            return node == left || (right!=null && id2childNodes.get(left.id).contains(node.id));
        }

        boolean comeFromRight(LeafNode node) {
            return node == right || (right!=null && id2childNodes.get(right.id).contains(node.id));
        }

        Vector<Path> returnTrueLeftPaths() {
            Vector<Path> result = new Vector<>();
            if (left != null && !(left instanceof LookaroundNode)) result.addAll(left.getPaths());
            return result;
        }

        Vector<Path> returnTrueRightPaths() {
            Vector<Path> result = new Vector<>();
            if (right != null && !(right instanceof LookaroundNode)) result.addAll(right.getPaths());
            return result;
        }

        boolean beginInLeftPath() {
            if (left != null && !(left instanceof LookaroundNode)) return left.beginInPath;
            return false;
        }

        boolean endInRight() {
            if (right != null && !(right instanceof LookaroundNode)) return right.endInPath;
            return false;
        }

        @Override
        ConnectNode copy(LeafNode father, Set<Integer> groupNums) {
            ConnectNode result =  new ConnectNode(null, null, groupNums);
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "<br>"
                    + (debug ? "groupNums:" + groupNums.toString() + "<br>" : "")
                    + (debug ? "id:" + this.id + "<br>" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex.replace("\"", "\\x22") + "<br>" : "")
                    + (debug&&debugFirstAndLast ? "first:{" + printSet(first, true) + "}<br>" : "")
                    + (debug&&debugFirstAndLast ? "last:{" + printSet(last, true) + "}<br>" : "")
                    +(debug ? printPaths(this.getRealPaths(), true) : "")+"\"]");
        }
    }

    // 分支结构
    private class BranchNode extends LinkNode {
        Vector<LeafNode> children;
        Map<LeafNode, Vector<Path>> childrenPaths;

        BranchNode (Pattern.Node actualNode, Set<Integer> groupNums) {
            super(groupNums, actualNode);
            children = new Vector<>();
            childrenPaths = new HashMap<>();
        }

        void addChild (LeafNode child) {
            if (child != null) {
                children.add(child);
                child.father = this;
            }
        }

        @Override
        public void generatePaths() {
            if (pathGenerated) return;
            // assignId2Node(this);
            this.beginInPath = true;
            this.endInPath = true;
            for (LeafNode child : children) {
                if (threadInterrupt("", false)) return;

                childrenPaths.put(child, new Vector<>(child.getPaths()));
                if (!(child instanceof LookaroundNode)) {
                    this.paths.addAll(child.getPaths());
                    if (!child.beginInPath) this.beginInPath = false;
                    if (!child.endInPath) this.endInPath = false;
                }
                else {
                    Path tmpPath = new Path();
                    PathNode tmpPathNode = new PathNode(child.getPaths(), ((LookaroundNode) child).type);
                    tmpPath.add(tmpPathNode);
                    this.paths.add(tmpPath);
                }
            }
            Collections.sort((this.paths), new Comparator<Path>() {
                @Override
                public int compare(Path o1, Path o2) {
                    return o1.getRealCharSize() - o2.getRealCharSize();
                }
            });
        }

        @Override
        void generateSelfRegex() {
            this.SelfRegex = "(";
            int count = 0;
            for (LeafNode child : children) {
                if (threadInterrupt("", false)) return;

                if (child != null) {
                    if (count != 0) this.SelfRegex += "|";
                    this.SelfRegex += child.SelfRegex;
                    count++;
                }
            }
            this.SelfRegex += ")";
        }


        @Override
        public void generateFistAndLast(){
            boolean allChildrenCouldBeEmpty = true;
            for (LeafNode child : children) {
                if (threadInterrupt("", false)) return;

                if (child != null && !(child instanceof LookaroundNode)) {
                    if (child.couldBeEmpty) allChildrenCouldBeEmpty = false;
                    this.first.addAll(child.first);
                    this.last.addAll(child.last);
                }
            }
            if (allChildrenCouldBeEmpty) this.couldBeEmpty = true;
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            for (int i = 0; i < children.size(); i++) {
                if (threadInterrupt("", false)) return;

                if (children.get(i) == oldNode) {
                    children.set(i, newNode);
                    if (newNode != null) newNode.father = this;
                    childrenPaths.put(newNode, childrenPaths.get(oldNode));
                    childrenPaths.remove(oldNode);
                    break;
                }
            }
        }

        @Override
        BranchNode copy(LeafNode father, Set<Integer> groupNums) {
            BranchNode result =  new BranchNode(this.actualNode, groupNums);
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "<br>"
                    + (debug ? "groupNums:" + groupNums.toString() + "<br>" : "")
                    + (debug ? "id:" + this.id + "<br>" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex.replace("\"", "\\x22") + "<br>" : "")
                    + (debug&&debugFirstAndLast ? "first:{" + printSet(first, true) + "}<br>" : "")
                    + (debug&&debugFirstAndLast ? "last:{" + printSet(last, true) + "}<br>" : "")
                    +(debug ? printPaths(this.getRealPaths(), true) : "")+"\"]");
        }
    }

    // 循环结构
    private class LoopNode extends LinkNode {
        int cmin;
        int cmax;
        LeafNode atom;
        Vector<Path> atomPaths;

        LoopNode (int cmin, int cmax, LeafNode atom, Pattern.Node actualNode, Set<Integer> groupNums) {
            super(groupNums, actualNode);
            this.cmin = cmin;
            this.cmax = cmax;
            this.atom = atom;
            if (atom != null) atom.father = this;
        }

        @Override
        public void generatePaths() {
            if (pathGenerated) return;
            // assignId2Node(this);
            this.atomPaths = new Vector<>();
            if (atom != null) {
                if (!(atom instanceof LookaroundNode)) {
                    this.atomPaths.addAll(atom.getPaths());
                    if (cmin != 0) this.beginInPath = atom.beginInPath;
                    if (cmin != 0) this.endInPath = atom.endInPath;
                }
                else {
                    Path path = new Path();
                    PathNode pathNode = new PathNode(atom.getPaths(), ((LookaroundNode) atom).type);
                    path.add(pathNode);
                    this.atomPaths.add(path);
                }
            }

            // Vector<Vector<Set<Integer>>> lastPaths = new Vector<>();
            // lastPaths.add(new Vector<>());
            Vector<Path> lastPaths = new Vector<>();
            lastPaths.add(new Path());

            for (int i = 0; i < cmin && !Thread.currentThread().isInterrupted(); i++) {
                Vector<Path> newPaths = new Vector<>();
                for (Path atomPath : atomPaths) {
                    if (atomPath.getRealCharSize() == 0) continue;
                    for (Path lastPath : lastPaths) {
                        if (threadInterrupt("", false)) return;

                        if (lastPath.getRealCharSize() + atomPath.getRealCharSize() > maxLength) {
                            continue;
                        }
                        Path newPath = new Path();
                        newPath.addAll(lastPath);
                        newPath.addAll(atomPath);
                        newPaths.add(newPath);
                    }
                }
                lastPaths = newPaths;
            }

            this.paths = new Vector<>();
            for (int i = cmin; i < cmax && i < maxLength && !Thread.currentThread().isInterrupted(); i++) {
                this.paths.addAll(lastPaths);
                Vector<Path> newPaths = new Vector<>();
                for (Path atomPath : atomPaths) {
                    if (atomPath.getRealCharSize() == 0) continue;
                    for (Path lastPath : lastPaths) {
                        if (threadInterrupt("", false)) return;

                        if (lastPath.getRealCharSize() + atomPath.getRealCharSize() > maxLength) {
                            continue;
                        }
                        Path newPath = new Path();
                        newPath.addAll(lastPath);
                        newPath.addAll(atomPath);
                        newPaths.add(newPath);
                    }
                }
                lastPaths = newPaths;
            }
            this.paths.addAll(lastPaths);

            Collections.sort((this.paths), new Comparator<Path>() {
                @Override
                public int compare(Path o1, Path o2) {
                    return o1.getRealCharSize() - o2.getRealCharSize();
                }
            });
        }

        @Override
        void generateSelfRegex(){
            if (atom != null) {
                this.SelfRegex += "(" + atom.SelfRegex + ")" + "{" + cmin + "," + (cmax > 100 ? "100" : cmax) + "}";
            }
        }


        @Override
        public void generateFistAndLast(){
            if (atom != null && !(atom instanceof LookaroundNode)) {
                if (atom.couldBeEmpty) this.couldBeEmpty = true;
                this.first = atom.first;
                this.last = atom.last;
            }
            if (cmin == 0) {
                this.couldBeEmpty = true;
            }
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            this.atom = newNode;
            if (newNode != null) newNode.father = this;
            // this.atomPaths = new Vector<>(newNode.paths);
        }

        @Override
        LoopNode copy(LeafNode father, Set<Integer> groupNums) {
            LoopNode result =  new LoopNode(cmin, cmax, null, this.actualNode, groupNums);
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "<br>"
                    + (debug ? "groupNums:" + groupNums.toString() + "<br>" : "")
                    + (debug ? "id:" + this.id + "<br>" : "")
                    + "cmin = " + cmin + "<br>cmax = " + cmax + "<br>"
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex.replace("\"", "\\x22") + "<br>" : "")
                    + (debug&&debugFirstAndLast ? "first:{" + printSet(first, true) + "}<br>" : "")
                    + (debug&&debugFirstAndLast ? "last:{" + printSet(last, true) + "}<br>" : "")
                    +(debug ? printPaths(this.getRealPaths(), true) : "")+"\"]");
        }
    }

    enum lookaroundType {
        Pos, Neg, Behind, NotBehind
    }

    // lookaround用一个一元结构独立出来
    private class LookaroundNode extends LinkNode {
        LeafNode atom;
        lookaroundType type;

        LookaroundNode(LeafNode atom, lookaroundType type, Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.atom = atom;
            this.type = type;
            if (atom != null) atom.father = this;
        }

        @Override
        public void generatePaths() {
            if (pathGenerated) return;
            // assignId2Node(this);
            this.paths.addAll(atom.getPaths());
            this.beginInPath = atom.beginInPath;
            this.endInPath = atom.endInPath;
        }

        @Override
        void generateSelfRegex(){
            if (atom != null) {
                switch (type) {
                    case Pos:
                        this.SelfRegex += "(?=" + atom.SelfRegex + ")";
                        break;
                    case Neg:
                        this.SelfRegex += "(?!" + atom.SelfRegex + ")";
                        break;
                    case Behind:
                        this.SelfRegex += "(?<=" + atom.SelfRegex + ")";
                        break;
                    case NotBehind:
                        this.SelfRegex += "(?<!" + atom.SelfRegex + ")";
                        break;
                }
            }
        }


        @Override
        public void generateFistAndLast(){
            if (atom != null) {
                if (atom.couldBeEmpty) this.couldBeEmpty = true;
                this.first = atom.first;
                this.last = atom.last;
            }
        }

        @Override
        void replaceChild(LeafNode oldNode, LeafNode newNode) {
            this.atom = newNode;
            if (newNode != null) newNode.father = this;
            // this.paths = new Vector<>(newNode.paths);
        }

        @Override
        LookaroundNode copy(LeafNode father, Set<Integer> groupNums) {
            LookaroundNode result =  new LookaroundNode(null, type, groupNums, this.actualNode);
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "<br>"
                    + (debug ? "groupNums:" + groupNums.toString() + "<br>" : "")
                    + (debug ? "id:" + this.id + "<br>" : "")
                    + "type = " + type.toString() + "<br>"
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex.replace("\"", "\\x22") + "<br>" : "")
                    + (debug&&debugFirstAndLast ? "first:{" + printSet(first, true) + "}<br>" : "")
                    + (debug&&debugFirstAndLast ? "last:{" + printSet(last, true) + "}<br>" : "")
                    +(debug ? printPaths(this.getRealPaths(), true) : "")+"\"]");
        }
    }

    // 反向引用
    private class BackRefNode extends LeafNode {
        int groupIndex;
        BackRefNode (int groupIndex, Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.groupIndex = groupIndex;
        }

        @Override
        BackRefNode copy(LeafNode father, Set<Integer> groupNums) {
            BackRefNode result = new BackRefNode(groupIndex, groupNums, this.actualNode);
            result.father = father;
            return result;
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+this.toString().replace("regex.Analyzer$", "").replace("@", "_") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + "groupIndex = " + groupIndex + "\\n"
                    + "localIndex = " + groupIndex2LocalIndex.get(groupIndex) + "\\n"
                    +(debug ? printPaths(this.getRealPaths(), true) : "")+"\"]");
        }
    }

    // 整个正则的终止符节点
    private class LastNode extends LeafNode {
        LastNode (Pattern.Node lastNode, Set<Integer> groupNums) {
            super(groupNums, lastNode);
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_"));
        }
    }

    // "^"符号
    private class Begin extends LeafNode {
        Begin (Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.beginInPath = true;
        }

        @Override
        void generateSelfRegex() {
            this.SelfRegex = "^";
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+ "^" + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex.replace("\"", "\\x22") + "\\n" : "")
                    +"\"]");
        }
    }

    // "$"符号
    private class End extends LeafNode {
        End (Set<Integer> groupNums, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.endInPath = true;
        }

        @Override
        void generateSelfRegex() {
            this.SelfRegex = "$";
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+ "$" + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex.replace("\"", "\\x22") + "\\n" : "")
                    +"\"]");
        }
    }

    // "\b"符号或者"\B"符号，\b为type3，\B为type4
    private class WordBoundary extends LeafNode {
        int type;
        WordBoundary (Set<Integer> groupNums, int type, Pattern.Node actualNode) {
            super(groupNums, actualNode);
            this.endInPath = true;
            this.type = type;
        }

        @Override
        void generateSelfRegex() {
            this.SelfRegex = type == 3 ? "\\b" : "\\B";
        }

        @Override
        public void generatePaths() {
            if (pathGenerated) return;
            this.paths = new Vector<>();
            Path path = new Path();
            path.add(new PathNode(type == 3 ? PathNode.boundType.lower : PathNode.boundType.upper));
            this.paths.add(path);
        }

        @Override
        void print(boolean debug) {
            System.out.println(this.toString().replace("regex.Analyzer$", "").replace("@", "_")
                    +"[\""+ (this.type == 3 ? "\\b" : "\\B") + "\\n"
                    + (debug ? "groupNums:" + groupNums.toString() + "\\n" : "")
                    + (debug ? "id:" + this.id + "\\n" : "")
                    + (debug&&debugRegex ? "SelfRegex:" + this.SelfRegex.replace("\"", "\\x22") + "\\n" : "")
                    +"\"]");
        }
    }

    /**
     * 为一个节点生成对应的前缀路径
     * @param countingNode 需要生成前缀路径的节点
     * @return 该节点的前缀路径
     */
    private Vector<Path> generatePrePath(LeafNode countingNode) {
        LeafNode node = countingNode;
        Vector<Path> result = new Vector<>();
        while (node != this.root && !Thread.currentThread().isInterrupted()) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromRight(node)) {
                // Vector<Vector<Set<Integer>>> left = ((ConnectNode) father).returnTrueLeftPaths();
                Vector<Path> tmp = splicePath(((ConnectNode) father).returnTrueLeftPaths(), result);
                if (result.size() != 0 && tmp.size() == 0) {
                    return new Vector<>();
                }
                result = tmp;
            }
            // else if (father instanceof LoopNode && ((LoopNode) father).cmin == 0) {
            //     result.add(new Vector<>());
            // }
            node = father;
        }
        if (result.size() == 0) result.add(new Path());
        return result;
    }

    private String generatePreRegex(LeafNode countingNode) {
        LeafNode node = countingNode;
        String result = "";
        while (node != this.root && !Thread.currentThread().isInterrupted()) {
            LeafNode father = node.father;
            if (father instanceof ConnectNode && ((ConnectNode) father).comeFromRight(node)) {
                result = (((ConnectNode) father).left == null) ? "" : ((ConnectNode) father).left.SelfRegex + result;
            }
            node = father;
        }
        return result;
    }

    /**
     * 将传入的两个路径排列组合地拼接在一起，同时满足生成结果小于全局的maxlength限制
     * @param prefix 被生成路径的前缀
     * @param suffix 被生成路径的后缀
     * @return 前缀+后缀
     */
    private Vector<Path> splicePath(Vector<Path> prefix, Vector<Path> suffix) {
        Vector<Path> result = new Vector<>();
        if (prefix.size() == 0) {
            result.addAll(suffix);
        }
        else if (suffix.size() == 0) {
            result.addAll(prefix);
        }
        else {
            for (Path prefixPath : prefix) {
                for (Path suffixPath : suffix) {
                    if (threadInterrupt("", false)) return result;

                    if (prefixPath.getRealCharSize() + suffixPath.getRealCharSize() <= maxLength) {
                        Path newPath = new Path();
                        newPath.addAll(prefixPath);
                        newPath.addAll(suffixPath);
                        result.add(newPath);
                    }
                }
            }
        }
        return result;
    }

    /**
     * 遍历路径，检查记录所有countingNode
     * @param root 根节点
     * @param inLookaround 是否在lookaround中
     */
    private void scanAllPath(LeafNode root, boolean inLookaround) {
        if (threadInterrupt("", false)) return;

        if (root == null) {
            return;
        }
        else {
            assignId2Node(root);
            if (root instanceof ConnectNode) {
                if (((ConnectNode) root).left != null) {
                    scanAllPath(((ConnectNode) root).left, inLookaround);
                    id2childNodes.get(root.id).add(((ConnectNode) root).left.id);
                    id2childNodes.get(root.id).addAll(id2childNodes.get(((ConnectNode) root).left.id));
                }
                if (((ConnectNode) root).right != null) {
                    scanAllPath(((ConnectNode) root).right, inLookaround);
                    id2childNodes.get(root.id).add(((ConnectNode) root).right.id);
                    id2childNodes.get(root.id).addAll(id2childNodes.get(((ConnectNode) root).right.id));
                }
            }
            else if (root instanceof BranchNode) {
                for (LeafNode node : ((BranchNode) root).children) {
                    if (node != null) {
                        scanAllPath(node, inLookaround);
                        id2childNodes.get(root.id).add(node.id);
                        id2childNodes.get(root.id).addAll(id2childNodes.get(node.id));
                    }
                }
            }
            else if (root instanceof LoopNode) {
                if (((LoopNode) root).atom != null) {
                    scanAllPath(((LoopNode) root).atom, inLookaround);
                    id2childNodes.get(root.id).add(((LoopNode) root).atom.id);
                    id2childNodes.get(root.id).addAll(id2childNodes.get(((LoopNode) root).atom.id));
                }
                if(!inLookaround) countingNodes.add(root);
            }
            else if (root instanceof LookaroundNode) {
                if (((LookaroundNode) root).atom != null) {
                    scanAllPath(((LookaroundNode) root).atom, true);
                    id2childNodes.get(root.id).add(((LookaroundNode) root).atom.id);
                    id2childNodes.get(root.id).addAll(id2childNodes.get(((LookaroundNode) root).atom.id));
                }
            }
            else {
                // LeafNode
                root.generatePaths();
            }

            root.generateSelfRegex();
            root.generateFistAndLast();
        }
    }

    /**
     * 对传入的树，递归地生成每一个节点的Path，同时记录每个循环节点，并为每个节点分配id且记录每个节点下属所有孩子节点的id
     * @param root 根节点
     */

    private synchronized void generateAllPath(LeafNode root) {
        if (threadInterrupt("", false)) return;

        if (root == null) {
            return;
        }
        else if (root instanceof LinkNode) {
            if (root instanceof ConnectNode) {
                generateAllPath(((ConnectNode) root).left);
                generateAllPath(((ConnectNode) root).right);
                ((ConnectNode) root).generatePaths();
            }
            else if (root instanceof BranchNode) {
                for (LeafNode node : ((BranchNode) root).children) {
                    generateAllPath(node);
                }
                ((BranchNode) root).generatePaths();
            }
            else if (root instanceof LoopNode) {
                generateAllPath(((LoopNode) root).atom);
                ((LoopNode) root).generatePaths();
            }
            else if (root instanceof LookaroundNode) {
                generateAllPath(((LookaroundNode) root).atom);
                ((LookaroundNode) root).generatePaths();
            }
        }
        else if (root instanceof LeafNode) {
            root.generatePaths();
        }
        root.pathGenerated = true;
    }

    private void assignId2Node(LeafNode node) {
        node.id = id++;
        id2childNodes.put(node.id, new HashSet<>());
    }

    /**
     * 根据优化要求，对整个正则树进行修改，返回实际用来生成路径的新树
     * @param root 原始的正则表达书
     * @return 经过优化后的用来生成路径的树
     */
    private LeafNode buildFinalTree(LeafNode root) {
        // 1. 反向引用替换（不支持嵌套）
        for (LeafNode node : backRefNodes) {
            int localIndex = groupIndex2LocalIndex.get(((BackRefNode)node).groupIndex);
            LeafNode rawGroupRoot = groupStartNodesMap.get(localIndex);
            ((LinkNode)node.father).replaceChild(node, copyGroupTree(rawGroupRoot, groupIndex2LocalIndex.get(((BackRefNode)node).groupIndex), node.father, node.groupNums));
        }

        if (threadInterrupt("", false)) return null;

        // 2. 判断是否在前部加入.{0,3}
        if (branchAtFirst(root) == 1) {
            // 在前部加入.{0,3}
            Pattern dotPattern = Pattern.compile(".{0,3}");
            DotNode = buildTree(dotPattern.root, new HashSet<>());

            root = new ConnectNode(DotNode, root, new HashSet<>());
        }

        if (threadInterrupt("", false)) return null;

        // 3. 是将结尾的lookaround拿出还是在尾部添加[\s\S]*
        // a. 如果结尾单独一个lookaround，则需要把lookaround拿出来缀在末尾
        searchLookaroundAtLast(root);
        if (threadInterrupt("", false)) return root;

        if (lookaroundAtLast.size() == 1) {
            ((LinkNode)lookaroundAtLast.get(0).father).replaceChild(lookaroundAtLast.get(0), ((LookaroundNode)lookaroundAtLast.get(0)).atom);
        }
        // b. 如果结尾有多个连续的lookaround，则需要在结尾加上[\s\S]*
        if (lookaroundAtLast.size() > 1) {
            for (LeafNode node : lookaroundAtLast) {
                if (threadInterrupt("", false)) return root;

                ((LinkNode)node.father).replaceChild(node, null);
            }
            Pattern tailPattern = Pattern.compile("[\\s\\S]*");
            LeafNode tailTree = buildTree(tailPattern.root, new HashSet<>());
            root = new ConnectNode(root, tailTree, new HashSet<>());
        }

        // 4. 在树外围包裹ConnectNode--right-->LastNode
        root = new ConnectNode(root, new LastNode(lastNode, new HashSet<>()), new HashSet<>());
        return root;
    }

    /**
     * 根据传入的组号，拷贝所有带有此组号的节点，组成新树
     * @param root 带有特定组号的树的根节点
     * @param localIndex 组号
     * @param father 新节点的父节点
     * @param groupNums 被替换的原节点的组号，要被替换到新的树中
     * @return 拷贝出来的新节点
     */
    private LeafNode copyGroupTree(LeafNode root, int localIndex, LeafNode father, Set<Integer> groupNums) {
        if (threadInterrupt("", false)) return null;

        LeafNode result = null;
        if (root == null){
            return null;
        }
        else if (root.groupNums.contains(localIndex)) {
            result = root.copy(father, groupNums);
            if (root instanceof Analyzer.ConnectNode) {
                ((Analyzer.ConnectNode)result).left = copyGroupTree(((ConnectNode)root).left, localIndex, result, groupNums);
                ((Analyzer.ConnectNode)result).left = copyGroupTree(((ConnectNode)root).left, localIndex, result, groupNums);
            }
            else if (root instanceof Analyzer.BranchNode) {
                for (LeafNode child : ((BranchNode)root).children) {
                    ((BranchNode)result).children.add(copyGroupTree(child, localIndex, result, groupNums));
                }
            }
            else if (root instanceof Analyzer.LoopNode) {
                ((LoopNode)result).atom = copyGroupTree(((LoopNode)root).atom, localIndex, result, groupNums);
            }
            else if (root instanceof Analyzer.LookaroundNode) {
                ((LookaroundNode)result).atom = copyGroupTree(((LookaroundNode)root).atom, localIndex, result, groupNums);
            }
        }
        else {
            return null;
        }
        return result;
    }

    /**
     * 递归建立原始的正则表达式树
     * @param root Pattern.Node节点
     * @param rawgroupNums 从递归上层传下来的组号
     * @return 本层递归节点需要返回的LeafNode
     */
    private LeafNode buildTree(Pattern.Node root, Set<Integer> rawgroupNums) {
        if (threadInterrupt("", false)) return null;

        LeafNode result = null;
        LeafNode me = null;
        LeafNode brother = null;
        Set<Integer> groupNums = new HashSet<>(rawgroupNums);
        if (root == null || (root instanceof Pattern.GroupTail && root.next instanceof Pattern.Loop)) {
            return null;
        }
        else if (root instanceof Pattern.LastNode) {
            lastNode = root;
            return null;
        }

        else if (root instanceof Pattern.GroupHead) {
            groupNums.add(((Pattern.GroupHead) root).localIndex);
            result = buildTree(root.next, groupNums);
            groupStartNodesMap.put(((Pattern.GroupHead) root).localIndex, result);
            return result;
        }
        else if (root instanceof Pattern.GroupTail) {
            groupNums.remove(((Pattern.GroupTail) root).localIndex);
            groupIndex2LocalIndex.put(((Pattern.GroupTail) root).groupIndex, ((Pattern.GroupTail) root).localIndex);
            return buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.BackRef || root instanceof Pattern.CIBackRef || root instanceof Pattern.GroupRef) {
            me = new BackRefNode(((Pattern.BackRef)root).groupIndex, groupNums, root);
            backRefNodes.add(me);
            brother = buildTree(root.next, groupNums);
        }

        // 需要特殊处理的节点（下一个节点不在next或者不止在next）
        else if (root instanceof Pattern.Prolog) {
            return buildTree(((Pattern.Prolog)root).loop, groupNums);
        }
        else if (root instanceof Pattern.Loop) {
            me = new LoopNode(((Pattern.Loop)root).cmin, ((Pattern.Loop)root).cmax, buildTree(((Pattern.Loop)root).body, groupNums), root, groupNums);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Curly) {
            me = new LoopNode(((Pattern.Curly)root).cmin, ((Pattern.Curly)root).cmax, buildTree(((Pattern.Curly)root).atom, groupNums), root, groupNums);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.GroupCurly) {
            groupNums.add(((Pattern.GroupCurly) root).groupIndex);
            me = new LoopNode(((Pattern.GroupCurly)root).cmin, ((Pattern.GroupCurly)root).cmax, buildTree(((Pattern.GroupCurly)root).atom, groupNums), root, groupNums);
            brother = buildTree(root.next, groupNums);
        }

        // 2. 分支
        else if(root instanceof Pattern.Branch){
            if (((Pattern.Branch) root).getSize() == 1) {
                me = new LoopNode(0,1, buildTree(((Pattern.Branch)root).atoms[0], groupNums), root, groupNums);
            }
            else {
                me = new BranchNode(root, groupNums);
                for (Pattern.Node node : ((Pattern.Branch) root).atoms) {
                    if (node == null) {
                        continue;
                    }
                    ((BranchNode) me).addChild(buildTree(node, groupNums));
                }
            }
            brother = buildTree(((Pattern.Branch) root).conn.next, groupNums);
        }
        else if (root instanceof Pattern.BranchConn) {
            return null;
        }
        else if(root instanceof Pattern.Ques){
            me = new LoopNode(0,1, buildTree(((Pattern.Ques)root).atom, groupNums), root, groupNums);
            brother = buildTree(root.next, groupNums);
        }

        // 具有实际字符意义
        else if (root instanceof Pattern.CharProperty){
            // generateFullSmallCharSet((Pattern.CharProperty) root);
            generateRawCharSet((Pattern.CharProperty) root, true);

            me = new LeafNode(groupNums, root);

            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.SliceNode){
            me = new LeafNode(groupNums, root);
            // Vector<Set<Integer>> tmpPath = new Vector<>();
            Path tmpPath = new Path();
            for (int i : ((Pattern.SliceNode) root).buffer) {
                fullSmallCharSet.add(i);
                if (i > 256) need256 = true;
                if (i > 65536) need65536 = true;

                Set<Integer> tmpCharSet = new HashSet<>();
                tmpCharSet.add(i);
                // tmpPath.add(tmpCharSet);
                PathNode tmpNode = new PathNode(tmpCharSet);
                tmpPath.add(tmpNode);
            }
            // me.paths.add(tmpPath);
            me.paths.add(tmpPath);
            me.pathGenerated = true;

            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.BnM) {
            me = new LeafNode(groupNums, root);
            // Vector<Set<Integer>> tmpPath = new Vector<>();
            Path tmpPath = new Path();
            for (int i : ((Pattern.BnM) root).buffer) {
                fullSmallCharSet.add(i);
                if (i > 256) need256 = true;
                if (i > 65536) need65536 = true;

                Set<Integer> tmpCharSet = new HashSet<>();
                tmpCharSet.add(i);
                // tmpPath.add(tmpCharSet);
                PathNode tmpNode = new PathNode(tmpCharSet);
                tmpPath.add(tmpNode);
            }
            me.paths.add(tmpPath);
            me.pathGenerated = true;

            brother = buildTree(root.next, groupNums);
        }

        // lookaround处理
        else if (root instanceof Pattern.Pos){
            haveAdvancedFeatures = true;
            me = new LookaroundNode(buildTree(((Pattern.Pos)root).cond, groupNums), lookaroundType.Pos, groupNums, root);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Neg){
            haveAdvancedFeatures = true;
            me = new LookaroundNode(buildTree(((Pattern.Neg)root).cond, groupNums), lookaroundType.Neg, groupNums, root);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Behind){
            haveAdvancedFeatures = true;
            me = new LookaroundNode(buildTree(((Pattern.Behind)root).cond, groupNums), lookaroundType.Behind, groupNums, root);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.NotBehind){
            haveAdvancedFeatures = true;
            me = new LookaroundNode(buildTree(((Pattern.NotBehind)root).cond, groupNums), lookaroundType.NotBehind, groupNums, root);
            brother = buildTree(root.next, groupNums);
        }

        // "^"、"$"
        else if (root instanceof Pattern.Begin || root instanceof Pattern.Caret || root instanceof Pattern.UnixCaret) {
            me = new Begin(groupNums, root);
            brother = buildTree(root.next, groupNums);
        }
        else if (root instanceof Pattern.Dollar || root instanceof Pattern.UnixDollar) {
            me = new End(groupNums, root);
            brother = buildTree(root.next, groupNums);
        }

        // "\b"、"\B"
        else if (root instanceof Pattern.Bound) {
            haveAdvancedFeatures = true;
            me = new WordBoundary(groupNums, ((Pattern.Bound) root).type, root);
            brother = buildTree(root.next, groupNums);
        }

        else {
            return buildTree(root.next, groupNums);
        }


        if (brother != null) {
            result = new ConnectNode(me, brother, groupNums);
            return result;
        } else {
            return me;
        }
    }

    /**
     * 生成所有“实际字符”节点的原始内容，记录“小字符全集”和“大字符集”节点
     * @param root
     */
    private void generateFullSmallCharSet(Pattern.CharProperty root) {
        Set<Integer> charSet = new HashSet<>();
        root.selfRegex = "";
        int count = 0;
        int charSetRange = (need65536 ? 65536 : (need256 ? 256 : 128));
        // for (int i = 0; i < 256 && !Thread.currentThread().isInterrupted(); i++) {
        for (int i = 0; i < charSetRange && !Thread.currentThread().isInterrupted(); i++) {
            if (root.isSatisfiedBy(i)) {
                charSet.add(i);

                count++;
                if (count == 1) {
                    String hex = Integer.toHexString(i);
                    while (hex.length() < 2) {
                        hex = "0" + hex;
                    }
                    root.selfRegex += "\\x"+hex;
                }
            }
            else {
                if (count > 1) {
                    // root.selfRegex += "-" + ((i==34||i==91||i==92) ? "\\" : "") + (char) (i - 1);
                    String hex = Integer.toHexString(i - 1);
                    while (hex.length() < 2) {
                        hex = "0" + hex;
                    }
                    root.selfRegex += "-" + "\\x"+hex;
                }
                count = 0;
            }
        }
        if (count > 1) {
            String hex = Integer.toHexString(255);
            root.selfRegex += "-" + "\\x"+hex;
        }


        if (charSet.size() < 128) {
            fullSmallCharSet.addAll(charSet);
        } else {
            bigCharSetMap.put(root, charSet);
        }
    }

    /**
     * 遍历bigCharSetMap，调用generateBigCharSet
     */
    private void generateAllBigCharSet() {
        // 遍历化bigCharSetMap节点
        for (Map.Entry<Pattern.CharProperty, Set<Integer>> entry : bigCharSetMap.entrySet()) {
            if (threadInterrupt("", false)) return;

            Pattern.CharProperty root = (Pattern.CharProperty) entry.getKey();
            generateBigCharSet(root);
        }

    }

    /**
     * 压缩所有“大字符集”节点的charSet
     * @param root
     */
    private void generateBigCharSet(Pattern.CharProperty root) {
        Random rand = new Random();

        if (bigCharSetMap.size() > 20) {
            // Set<Integer> charSet = new HashSet<>();
            // for (int i = 0; i < 256 && !Thread.currentThread().isInterrupted(); i++) {
            //     if (root.isSatisfiedBy(i)) {
            //         charSet.add(i);
            //     }
            // }
            // root.charSet.addAll(charSet);

            // 如果在新版charSet生成方式下总数还能超过128，那一定是需要256或65536的，直接加入和fullSmallCharSet的交集和10的其他的值
            Set<Integer> charSet = bigCharSetMap.get(root);

            Set<Integer> tmp = new HashSet<>(charSet);
            tmp.retainAll(fullSmallCharSet);
            root.charSet.addAll(tmp);

            charSet.removeAll(tmp);

            Integer[] arrayNumbers = charSet.toArray(new Integer[charSet.size()]);
            for (int i = 0; i < 10; i++) {
                int rndmNumber = rand.nextInt(bigCharSetMap.get(root).size());
                root.charSet.add(arrayNumbers[rndmNumber]);
            }
            return;
        }

        Set<Integer> result = new HashSet<>();

        // set2&set8
        Set<Integer> tmp;

        for (Map.Entry<Pattern.CharProperty, Set<Integer>> entry : bigCharSetMap.entrySet()) {
            if (threadInterrupt("", false)) return;

            if (entry.getKey() == root) {
                // 加入root和fullSmallCharSet的交集
                // set2&set8
                tmp = new HashSet<>(entry.getValue());
                tmp.retainAll(fullSmallCharSet);
                result.addAll(tmp);
                continue;
            } else {
                // 加入和本bigCharSet的差集
                // (set2-set5)
                tmp = new HashSet<>(bigCharSetMap.get(root));
                tmp.removeAll(entry.getValue());
                result.addAll(tmp);

                // 随机加入一个root和本bigCharSet的并集-其他bigCharSet
                // random 1个(set2&set5-set7-set8)
                tmp = new HashSet<>(bigCharSetMap.get(root));
                tmp.retainAll(entry.getValue());
                tmp.removeAll(fullSmallCharSet);
                for (Map.Entry<Pattern.CharProperty, Set<Integer>> entry_ : bigCharSetMap.entrySet()) {
                    if (threadInterrupt("", false)) return;

                    if (entry_.getKey() == root || entry_.getKey() == entry.getKey()) {
                        continue;
                    } else {
                        tmp.removeAll(entry_.getValue());
                    }
                }

                if (tmp.size() > 0) {
                    int index = rand.nextInt(tmp.size());
                    Iterator<Integer> iter = tmp.iterator();
                    for (int i = 0; i < index && !Thread.currentThread().isInterrupted(); i++) {
                        iter.next();
                    }
                    result.add(iter.next());
                }
            }
        }

        // 最后random 1个(set2-set8)
        tmp = new HashSet<>(bigCharSetMap.get(root));
        tmp.removeAll(fullSmallCharSet);
        if (tmp.size() > 0) {
            int index = rand.nextInt(tmp.size());
            Iterator<Integer> iter = tmp.iterator();
            for (int i = 0; i < index && !Thread.currentThread().isInterrupted(); i++) {
                iter.next();
            }
            result.add(iter.next());
        }

        root.charSet.addAll(result);
    }

    /**
     * 后序遍历，捕获所有后缀为空的lookaround，直到遇到实际字符
     * @param root
     * @return 遇到实际字符返回false，可空返回true
     */
    private boolean searchLookaroundAtLast(LeafNode root) {
        if (threadInterrupt("", false)) return false;

        if (root == null || root.actualNode instanceof Pattern.CharProperty || root.actualNode instanceof Pattern.SliceNode || root.actualNode instanceof Pattern.BnM) {
            return false;
        }
        else if (root instanceof LookaroundNode && ((LookaroundNode) root).type == lookaroundType.Pos) {
            // 如果顺利遇到lookaround，放入lookaroundAtLast，假装可空继续向前找
            lookaroundAtLast.add(root);
            return true;
        }
        else if (root instanceof ConnectNode) {
            // 先看右边，右边如果遇到实际字符直接返回
            if (!searchLookaroundAtLast(((ConnectNode) root).right)) return false;

            // 右边如果可空则看左边，左边可空则整个节点可空，如实返回；左边遇到实际字符则说明不能继续，也直接返回
            return searchLookaroundAtLast(((ConnectNode) root).left);
        }
        else if (root instanceof BranchNode) {
            boolean tmp = false;
            for (LeafNode child : ((BranchNode) root).children) {
                if (searchLookaroundAtLast(child)) {
                    // 孩子中有一个可空，则视为整个Node可空
                    tmp = true;
                }
            }
            return tmp;
        }
        else if (root instanceof LoopNode) {
            // 看孩子是否可空
            boolean tmp = searchLookaroundAtLast(((LoopNode) root).atom);

            // 如果孩子遇到了实际字符，但是循环次数可以为0，那么返回可空
            if (!tmp && ((LoopNode) root).cmin == 0) return true;

                // 孩子可空、孩子不可空且循环次数不能为0等情况都如实返回
            else return tmp;
        }
        else {
            // 对于LastNode、Begin、End都返回可空，BackRefNode之前应该都处理过了（没处理说明是嵌套，也没办法了，不做处理）
            return true;
        }
    }

    /**
     * 判断是否有branch节点在开头
     * @param root
     * @return "实际字符"开头返回0，遇到可空字符返回2，遇到分支返回1
     */
    private int branchAtFirst (LeafNode root) {
        if (threadInterrupt("", false)) return 0;

        if (root.actualNode instanceof Pattern.CharProperty || root.actualNode instanceof Pattern.SliceNode || root.actualNode instanceof Pattern.BnM) {
            return 0;
        }
        else if (root instanceof BranchNode) {
            return 1;
        }
        else if (root instanceof ConnectNode) {
            // 先看左边，左边如果遇到实际字符或者以branch开头都如实返回
            int tmp = branchAtFirst(((ConnectNode) root).left);
            if (tmp == 0) return 0;
            else if (tmp == 1) return 1;

            // 左边如果可空则看右边，右边遇到实际字符或者以branch开头也如实返回
            tmp = branchAtFirst(((ConnectNode) root).right);
            if (tmp == 0) return 0;
            else if (tmp == 1) return 1;

                // 左右如果都可空，返回可空
            else return 2;
        }
        else if (root instanceof LoopNode) {
            // 看孩子是否能以branch开头
            int tmp = branchAtFirst(((LoopNode) root).atom);

            // 如果孩子遇到了实际字符，但是循环次数可以为0，那么返回可空
            if (tmp == 0 && ((LoopNode) root).cmin == 0) return 2;

                // branch开头，孩子也可空，孩子不可空且循环次数不能为0等情况都如实返回
            else return tmp;
        }
        else {
            // 对于Lookaround、LastNode、Begin、End都返回可空，BackRefNode之前应该都处理过了（没处理说明是嵌套，也没办法了，不做处理）
            return 2;
        }
    }

    /**
     * 将以传入节点为根的树，以Markdown中Mermaid语法打印在输出中
     * @param root 树的根节点
     * @param debug 是否打印详细信息（每个节点的路径、组号）
     */
    private void printTree(LeafNode root, boolean debug) {
        if (root == null) return;
        else if (root instanceof Analyzer.ConnectNode) {
            ((ConnectNode) root).print(debug);
            if (((ConnectNode)root).left != null) {
                System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_")+"--left-->"+((ConnectNode)root).left.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                printTree(((ConnectNode)root).left, debug);
            }
            if (((ConnectNode)root).right != null) {
                System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_")+"--right-->"+((ConnectNode)root).right.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                printTree(((ConnectNode)root).right, debug);
            }
        }
        else if (root instanceof Analyzer.BranchNode) {
            ((BranchNode) root).print(debug);
            for (LeafNode child : ((BranchNode)root).children) {
                if (child != null) {
                    System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_") + "--child-->" + child.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                    printTree(child, debug);
                }
            }
        }
        else if (root instanceof Analyzer.LoopNode) {
            ((LoopNode) root).print(debug);
            if (((LoopNode)root).atom != null) {
                System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_") + "--atom-->" + ((LoopNode) root).atom.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                printTree(((LoopNode) root).atom, debug);
            }
        }
        else if (root instanceof Analyzer.LookaroundNode) {
            ((LookaroundNode) root).print(debug);
            if (((LookaroundNode)root).atom != null) {
                System.out.println(root.toString().replace("regex.Analyzer$", "").replace("@", "_") + "--atom-->" + ((LookaroundNode) root).atom.toString().replace("regex.Analyzer$", "").replace("@", "_"));
                printTree(((LookaroundNode) root).atom, debug);
            }
        }
        else {
            root.print(debug);
        }
    }

    /**
     * 生成一组路径的字符串
     * @param paths Vector<Set<Integer>>格式路径的列表
     * @return 形如“[a,b,c],[d]\\n[a,b,c],[e]”的字符串，每条路径之间用"\\n"分割
     */
    private String printPaths (Vector<Vector<Set<Integer>>> paths, boolean mermaid) {
        String result = "";

        if (paths.size() > 30) {
            result = "paths.size():"+paths.size()+(mermaid ? "<br>" : "\n");
            for (int i = 0; i < 10; i++) {
                result += printPath(paths.get(i), mermaid);
                result += (mermaid ? "<br>" : "\n");
            }
            result += "...";
        }
        else {
            for (Vector<Set<Integer>> path : paths) {
                result += printPath(path, mermaid);
                result += mermaid ? "<br>" : "\n";
            }
        }
        return result;
    }

    /**
     * 用来生成一条Vector<Set<Integer>>的路径的字符串
     * @param path Vector<Set<Integer>>格式的路径
     * @return 形如“[a,b,c],[d]”的字符串，每个set用"[]"包裹，set之间用","分割
     */
    private String printPath (Vector<Set<Integer>> path, boolean mermaid) {
        String result = "";

        int indexP = 0;
        if (path.size() == 0) {
            return "null";
        }
        for (Set<Integer> s : path) {
            if (indexP != 0) {
                result += ",";
            }
            if (setsEquals(s, Dot)) {
                result += ".";
            }
            // else if (setsEquals(s, Bound)) {
            //     result += "\\b";
            // }
            else if (setsEquals(s, SpaceFull)) {
                result += "\\s";
            }
            else if (setsEquals(s, noneSpace)) {
                result += "\\S";
            }
            else if (setsEquals(s, word)) {
                result += "\\w";
            }
            else if (setsEquals(s, All)) {
                result += "\\s\\S";
            }
            else if (s.size() > 20) {
                result += "size(" + s.size() + ")";
            }
            else {
                result += "[";
                result += printSet(s, mermaid);
                result += "]";
            }
        }
        return result;
    }

    public String printSet(Set<Integer> s, boolean mermaid) {
        String result = "";
        int indexS = 0;
        for (int i : s) {
            if (indexS != 0) {
                result += ",";
            }
            indexS++;
            // System.out.print((char) i);
            result += int2String(i, mermaid);
        }
        return result;
    }

    /**
     * 用于判断两个set内容是否相同
     * @param set1
     * @param set2
     * @return 内容相同返回true，内容不同返回false
     */
    public boolean setsEquals(Set<?> set1, Set<?> set2) {
        //null就直接不比了
        if (set1 == null || set2 == null) {
            return false;
        }
        //大小不同也不用比了
        if (set1.size() != set2.size()) {
            return false;
        }
        //最后比containsAll
        return set1.containsAll(set2);
    }

    /**
     * 求两个集合的交集
     * @param set1
     * @param set2
     * @return
     */
    public Set<Integer> setsIntersection(Set<Integer> set1, Set<Integer> set2) {
        Set<Integer> result = new HashSet<Integer>(set1);
        result.retainAll(set2);
        return result;
    }

    /**
     * 求两个集合的并集
     * @param set1
     * @param set2
     * @return
     */
    public Set<Integer> setsMerge(Set<Integer> set1, Set<Integer> set2) {
        Set<Integer> result = new HashSet<Integer>(set1);
        result.addAll(set2);
        return result;
    }

    /**
     * 求两个集合的差集
     * @param set1
     * @param set2
     * @return
     */
    public Set<Integer> setsDifference(Set<Integer> set1, Set<Integer> set2) {
        Set<Integer> result = new HashSet<Integer>(set1);
        result.removeAll(set2);
        return result;
    }

    /**
     * 获得一个“实际字符”节点所有全部chaSet
     * @param node CharProperty、Slice、BnM类型的字符节点
     * @return 所有出现在节点中的字符的集合
     */
    private Set<Integer> getNodeCharSet(Pattern.CharProperty node) {
        if (node.charSet_0_128.size() == 0) {
            generateRawCharSet(node, false);
        }
        Set<Integer> tmp = new HashSet<>(node.charSet_0_128);
        if (need256) tmp.addAll(node.charSet_128_256);
        if (need65536) tmp.addAll(node.charSet_256_65536);
        return tmp;
    }

    /**
     * 生成原本应该被节点接受的全部字符集合，并将其存入节点的charSet_0_128等属性中
     * 同时生成selfRegex（selfRegex仅限256）
     * @param root CharProperty类型的节点
     */
    private void generateRawCharSet(Pattern.CharProperty root, boolean scan) {
        // 默认的处理方法
        root.selfRegex = "";
        int count = 0;
        for (int i = 0; i < 65536 && !Thread.currentThread().isInterrupted(); i++) {
            if (root.isSatisfiedBy(i)) {
                if (i < 128) root.charSet_0_128.add(i);
                else if (i < 256) root.charSet_128_256.add(i);
                else root.charSet_256_65536.add(i);

                if (i < 256) {
                    count++;
                    if (count == 1) {
                        String hex = Integer.toHexString(i);
                        while (hex.length() < 2) {
                            hex = "0" + hex;
                        }
                        root.selfRegex += "\\x" + hex;
                    }
                }
            }
            else if (i < 256) {
                if (count > 1) {
                    // root.selfRegex += "-" + ((i==34||i==91||i==92) ? "\\" : "") + (char) (i - 1);
                    String hex = Integer.toHexString(i - 1);
                    while (hex.length() < 2) {
                        hex = "0" + hex;
                    }
                    root.selfRegex += "-" + "\\x"+hex;
                }
                count = 0;
            }
        }
        if (count > 1) {
            String hex = Integer.toHexString(255);
            root.selfRegex += "-" + "\\x"+hex;
        }

        Set<Integer> charSet = new HashSet<>(root.charSet_0_128);
        charSet.addAll(root.charSet_128_256);
        charSet.addAll(root.charSet_256_65536);

        if (charSet.size() < 128) {
            fullSmallCharSet.addAll(charSet);
        } else {
            bigCharSetMap.put(root, charSet);
        }

        charPropertySet.add(root);

        if (scan) {
            // 排除Dot
            if (charSet.size() == 65531)
                if (!charSet.contains(10) && !charSet.contains(13) && !charSet.contains(133) && !charSet.contains(8232) && !charSet.contains(8233))
                    return;

            if (root.charSet_128_256.size() != 0 && root.charSet_128_256.size() != 128) need256 = true;
            if (root.charSet_256_65536.size() != 0 && root.charSet_256_65536.size() != 65280) need65536 = true;
        }
    }

    private void generateAllCharSet() {
        // 现根据是否需要256位和65536位来清洗一遍bigCharSetMap和fullSmallCharSet
        if (!(need256 && need65536)) {
            Set<Integer> removeSet = new HashSet<>();
            if (!need65536) {
                for (int i = 256; i < 65536; i++) {
                    removeSet.add(i);
                }
            }
            if (!need256) {
                for (int i = 128; i < 256; i++) {
                    removeSet.add(i);
                }
            }

            fullSmallCharSet.removeAll(removeSet);

            // for (Pattern.CharProperty charProperty : bigCharSetMap.keySet()) {
            //     bigCharSetMap.get(charProperty).removeAll(removeSet);
            //     if (bigCharSetMap.get(charProperty).size() < 128) {
            //         fullSmallCharSet.addAll(bigCharSetMap.get(charProperty));
            //         bigCharSetMap.remove(charProperty);
            //     }
            // }

            Iterator<Pattern.CharProperty> iterator = bigCharSetMap.keySet().iterator();
            while(iterator.hasNext()){
                Pattern.CharProperty integer = iterator.next();
                bigCharSetMap.get(integer).removeAll(removeSet);
                // 如果清洗后的集合变为小集合，则把这个节点从bigCharSetMap中移除
                if (bigCharSetMap.get(integer).size() < 128) {
                    fullSmallCharSet.addAll(bigCharSetMap.get(integer));
                    iterator.remove();
                }
            }

        }


        for (Pattern.CharProperty charProperty : charPropertySet) {
            if (bigCharSetMap.entrySet().contains(charProperty)) {
                generateBigCharSet(charProperty);
            }
            else {
                generateSmallCharSet(charProperty);
            }
        }
    }

    private void generateSmallCharSet(Pattern.CharProperty charProperty) {
        Set<Integer> tmpSet = new HashSet<>(charProperty.charSet_0_128);
        if (need256)  tmpSet.addAll(charProperty.charSet_128_256);
        if (need65536) tmpSet.addAll(charProperty.charSet_256_65536);

        charProperty.charSet.addAll(tmpSet);
    }
}
