package regex;

import java.util.HashSet;
import java.util.Set;

public class regexUtils {
    private static final Pattern SpaceP = Pattern.compile("\\s"); // Ctype type = 2048
    private static final Pattern noneSpaceP = Pattern.compile("\\S"); // Ctype type = 2048
    private static final Pattern wordP = Pattern.compile("\\w"); // Ctype type = 67328
    private static final Pattern noneWordP = Pattern.compile("\\W"); // Ctype type = 673
    private static final Pattern digitP = Pattern.compile("\\d"); // Ctype type = 8
    private static final Pattern noneDigitP = Pattern.compile("\\D"); // Ctype type = 8
    private static final Pattern AllP = Pattern.compile("[\\s\\S]");

    public static final Set<Integer> Space = getRawCharSet((Pattern.CharProperty) SpaceP.root.next);
    public static final Set<Integer> noneSpace = getRawCharSet((Pattern.CharProperty) noneSpaceP.root.next);
    public static final Set<Integer> word = getRawCharSet((Pattern.CharProperty) wordP.root.next);
    public static final Set<Integer> noneWord = getRawCharSet((Pattern.CharProperty) noneWordP.root.next);
    public static final Set<Integer> digit = getRawCharSet((Pattern.CharProperty) digitP.root.next);
    public static final Set<Integer> noneDigit = getRawCharSet((Pattern.CharProperty) noneDigitP.root.next);
    public static final Set<Integer> All = getRawCharSet((Pattern.CharProperty) AllP.root.next);

    public static Set<Integer> getRawCharSet(Pattern.CharProperty node) {
        Set<Integer> set = new HashSet<>();
        for (int i = 0; i < 256; i++) {
            if (node.isSatisfiedBy(i)) {
                set.add(i);
            }
        }
        return set;
    }

    public static String getNodeMermaidTree(String regex) {
        patternPrinter pp = new patternPrinter(regex);
        String result = pp.printPatternStruct();
        return result;
    }

    public static class patternPrinter {


        private Pattern pattern;
        private Set<Pattern.Node> visitedConn;

        public patternPrinter (String regex) {
            this.pattern = Pattern.compile(regex);
            this.visitedConn = new HashSet<>();
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

        public String printPatternStruct () {
            String result = "";
            // System.out.println("flowchart TD");
            result += "flowchart TD\n";
            result += travelAndPrint(this.pattern.root);
            // System.out.println("\nShow in Mermaid, visit: https://mermaid.live/");
            result += "\nShow in Mermaid, visit: https://mermaid.live/\n";
            return result;
        }

        public String travelAndPrint(Pattern.Node root){
            String result = "";
            if (root == null || (root instanceof Pattern.GroupTail && root.next instanceof Pattern.Loop)) {
                return "";
            }
            // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_"));
            result += root.toString().replace("regex.Pattern$", "").replace("@", "_")
                    + "[\""
                    + root.toString().replace("regex.Pattern$", "").replace("@", "_")
                    + "<br>regex:" + root.regex
                    + "\"]"
                    + "\n";

            // 需要特殊处理的节点（下一个节点不在next或者不止在next）
            if (root instanceof Pattern.Prolog) {
                // travelAndPrint(((Pattern.Prolog)root).loop);
                result += travelAndPrint(((Pattern.Prolog)root).loop);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--loop-->" + ((Pattern.Prolog)root).loop.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--loop-->" + ((Pattern.Prolog)root).loop.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }
            else if (root instanceof Pattern.Loop) {
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>cmin:"+ ((Pattern.Loop)root).cmin + ",cmax" + ((Pattern.Loop)root).cmax + "\"]");
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>cmin:"+ ((Pattern.Loop)root).cmin + ",cmax" + ((Pattern.Loop)root).cmax + "\"]\n";
                // travelAndPrint(((Pattern.Loop)root).body);
                result += travelAndPrint(((Pattern.Loop)root).body);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--body-->" + ((Pattern.Loop)root).body.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--body-->" + ((Pattern.Loop)root).body.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                // travelAndPrint(((Pattern.Loop)root).next);
                result += travelAndPrint(((Pattern.Loop)root).next);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }
            else if (root instanceof Pattern.Curly) {
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>cmin:"+ ((Pattern.Curly)root).cmin + ",cmax" + ((Pattern.Curly)root).cmax + "\"]");
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>cmin:"+ ((Pattern.Curly)root).cmin + ",cmax" + ((Pattern.Curly)root).cmax + "\"]\n";
                // travelAndPrint(((Pattern.Curly)root).atom);
                result += travelAndPrint(((Pattern.Curly)root).atom);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--atom-->" + ((Pattern.Curly)root).atom.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--atom-->" + ((Pattern.Curly)root).atom.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                // travelAndPrint(((Pattern.Curly)root).next);
                result += travelAndPrint(((Pattern.Curly)root).next);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }
            else if (root instanceof Pattern.GroupCurly) {
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>cmin:"+ ((Pattern.GroupCurly)root).cmin + ",cmax" + ((Pattern.GroupCurly)root).cmax + "\"]");
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "[\""
                        + root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "<br>cmin:"+ ((Pattern.GroupCurly)root).cmin
                        + ",cmax" + ((Pattern.GroupCurly)root).cmax
                        + "<br>localIndex:" + ((Pattern.GroupCurly)root).localIndex
                        + "<br>groupIndex:" + ((Pattern.GroupCurly)root).groupIndex
                        + "\"]\n";
                // travelAndPrint(((Pattern.GroupCurly)root).atom);
                result += travelAndPrint(((Pattern.GroupCurly)root).atom);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--atom-->" + ((Pattern.GroupCurly)root).atom.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--atom-->" + ((Pattern.GroupCurly)root).atom.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                // travelAndPrint(((Pattern.GroupCurly)root).next);
                result += travelAndPrint(((Pattern.GroupCurly)root).next);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }

            // 2. 分支
            else if(root instanceof Pattern.Branch){
                for(Pattern.Node node : ((Pattern.Branch)root).atoms){
                    if (node == null){
                        continue;
                    }
                    // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--atoms-->" + node.toString().replace("regex.Pattern$", "").replace("@", "_"));
                    result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--atoms-->" + node.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                    // travelAndPrint(node);
                    result += travelAndPrint(node);
                }
            }
            else if (root instanceof Pattern.BranchConn) {
                if (visitedConn.contains(root)) {
                    return "";
                } else {
                    visitedConn.add(root);
                    // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                    result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                    // travelAndPrint(root.next);
                    result += travelAndPrint(root.next);
                }
            }
            else if(root instanceof Pattern.Ques){
                // travelAndPrint(((Pattern.Ques)root).atom);
                result += travelAndPrint(((Pattern.Ques)root).atom);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--atom-->" + ((Pattern.Ques)root).atom.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--atom-->" + ((Pattern.Ques)root).atom.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                // travelAndPrint(((Pattern.Ques)root).next);
                result += travelAndPrint(((Pattern.Ques)root).next);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }

            // 具有实际字符意义
            // else if (root instanceof Pattern.CharProperty){
            //     if (root instanceof Pattern.Dot || root instanceof Pattern.UnixDot){
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>.\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>.\"]\n";
            //     }
            //     else if (setsEquals(getRawCharSet((Pattern.CharProperty) root), Space)){
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\s\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\s\"]\n";
            //     }
            //     else if (setsEquals(getRawCharSet((Pattern.CharProperty) root), noneSpace)){
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\S\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\S\"]\n";
            //     }
            //     else if (setsEquals(getRawCharSet((Pattern.CharProperty) root), digit)){
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\d\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\d\"]\n";
            //     }
            //     else if (setsEquals(getRawCharSet((Pattern.CharProperty) root), noneDigit)){
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\D\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\D\"]\n";
            //     }
            //     else if (setsEquals(getRawCharSet((Pattern.CharProperty) root), word)){
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\w\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\w\"]\n";
            //     }
            //     else if (setsEquals(getRawCharSet((Pattern.CharProperty) root), noneWord)){
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\W\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>\\W\"]\n";
            //     }
            //     else if (setsEquals(getRawCharSet((Pattern.CharProperty) root), All)){
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>[\\S\\s]\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>[\\S\\s]\"]\n";
            //     }
            //     else{
            //         generateRawCharSet((Pattern.CharProperty) root);
            //         // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>[" + ((Pattern.CharProperty) root).selfRegex + "]\"]");
            //         result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>[" + ((Pattern.CharProperty) root).selfRegex + "]\"]\n";
            //     }
            //     // travelAndPrint(root.next);
            //     result += travelAndPrint(root.next);
            //     // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
            //     result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            // }
            // else if (root instanceof Pattern.SliceNode){
            //     String slice = "";
            //     for (int i : ((Pattern.SliceNode)root).buffer) {
            //         slice += int2String(i, true);
            //     }
            //     // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>" + slice + "\"]");
            //     result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>" + slice + "\"]\n";
            //     // travelAndPrint(root.next);
            //     result += travelAndPrint(root.next);
            //     // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
            //     result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            // }
            // else if (root instanceof Pattern.BnM){
            //     String slice = "";
            //     for (int i : ((Pattern.BnM)root).buffer) {
            //         slice += int2String(i, true);
            //     }
            //     // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>" + slice + "\"]");
            //     result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "[\"" + root.toString().replace("regex.Pattern$", "").replace("@", "_") + "<br>" + slice + "\"]\n";
            //     // travelAndPrint(root.next);
            //     result += travelAndPrint(root.next);
            //     // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
            //     result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            // }

            // lookaround处理
            else if (root instanceof Pattern.Pos){
                // travelAndPrint(((Pattern.Pos)root).cond);
                result += travelAndPrint(((Pattern.Pos)root).cond);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--cond-->" + ((Pattern.Pos)root).cond.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--cond-->" + ((Pattern.Pos)root).cond.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                // travelAndPrint(((Pattern.Pos)root).next);
                result += travelAndPrint(((Pattern.Pos)root).next);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }
            else if (root instanceof Pattern.Neg){
                // travelAndPrint(((Pattern.Neg)root).cond);
                result += travelAndPrint(((Pattern.Neg)root).cond);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--cond-->" + ((Pattern.Neg)root).cond.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--cond-->" + ((Pattern.Neg)root).cond.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                // travelAndPrint(((Pattern.Neg)root).next);
                result += travelAndPrint(((Pattern.Neg)root).next);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }
            else if (root instanceof Pattern.Behind){
                // travelAndPrint(((Pattern.Behind)root).cond);
                result += travelAndPrint(((Pattern.Behind)root).cond);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--cond-->" + ((Pattern.Behind)root).cond.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--cond-->" + ((Pattern.Behind)root).cond.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                // travelAndPrint(((Pattern.Behind)root).next);
                result += travelAndPrint(((Pattern.Behind)root).next);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }
            else if (root instanceof Pattern.NotBehind){
                // travelAndPrint(((Pattern.NotBehind)root).cond);
                result += travelAndPrint(((Pattern.NotBehind)root).cond);
                // travelAndPrint(((Pattern.NotBehind)root).next);
                result += travelAndPrint(((Pattern.NotBehind)root).next);
                // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }

            // 组
            else if (root instanceof Pattern.GroupHead) {
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "[\""
                        + root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "<br>localIndex:" + ((Pattern.GroupHead)root).localIndex
                        + "\"]\n";
                result += travelAndPrint(root.next);
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }
            else if (root instanceof Pattern.GroupTail) {
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "[\""
                        + root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "<br>localIndex:" + ((Pattern.GroupTail)root).localIndex
                        + "<br>groupIndex:" + ((Pattern.GroupTail)root).groupIndex
                        + "\"]\n";
                result += travelAndPrint(root.next);
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }

            // 反向引用
            else if (root instanceof Pattern.BackRef) {
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "[\""
                        + root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "<br>regex:" + root.regex
                        + "<br>groupIndex:" + ((Pattern.BackRef)root).groupIndex
                        + "\"]\n";
                result += travelAndPrint(root.next);
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }

            // "\b"、"\B"
            else if (root instanceof Pattern.Bound) {
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "[\""
                        + root.toString().replace("regex.Pattern$", "").replace("@", "_")
                        + "<br>regex:" + root.regex
                        + "<br>type:" + ((Pattern.Bound)root).type
                        + "\"]\n";
                result += travelAndPrint(root.next);
                result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
            }

            else {
                // travelAndPrint(root.next);
                result += travelAndPrint(root.next);
                if (root.next != null) {
                    // System.out.println(root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_"));
                    result += root.toString().replace("regex.Pattern$", "").replace("@", "_") + "--next-->" + root.next.toString().replace("regex.Pattern$", "").replace("@", "_") + "\n";
                }
            }

            return result;
        }

        /**
         * 生成原本应该被节点接受的全部字符集合，并将其存入节点的charSet_0_128等属性中
         * 同时生成selfRegex（selfRegex仅限256）
         * @param root CharProperty类型的节点
         */
        private void generateRawCharSet(Pattern.CharProperty root) {
            // 默认的处理方法
            root.selfRegex = "";
            int count = 0;
            for (int i = 0; i < 65536 && !Thread.currentThread().isInterrupted(); i++) {
                if (root.isSatisfiedBy(i)) {
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
                    return mermaid ? "\\ n" : "\\n";
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
    }

    public static Set<Integer> getCharSet(Pattern.CharProperty root) {
        Set<Integer> charSet = new HashSet<>();
        for (int i = 0; i < 65536; i++) {
            if (root.isSatisfiedBy(i)) {
                charSet.add(i);
            }
        }
        return charSet;
    }
}
