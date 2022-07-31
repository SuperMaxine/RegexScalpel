package cn.ac.ios.Patterns.EOA;

import cn.ac.ios.TreeNode.TreeNode;
import cn.ac.ios.Bean.AttackBean;
import cn.ac.ios.Bean.AttackType;
import cn.ac.ios.Bean.ReDoSBean;
import cn.ac.ios.Utils.Constant;
import dk.brics.automaton.Automaton;

import java.util.*;

import static cn.ac.ios.TreeNode.Utils.*;
import static cn.ac.ios.Utils.BracketUtils.*;
import static cn.ac.ios.Utils.DkBricsAutomatonUtils.*;
import static cn.ac.ios.Utils.FlagsUtils.*;
import static cn.ac.ios.Utils.NegateUtils.*;
import static cn.ac.ios.Utils.RegexUtils.*;

public class PatternEOAUtils {
    public static TreeNode getRedosTree(String regex) throws InterruptedException {
        // 最开头的预处理
        regex = rewriteRegex(regex);
        regex = reduceLocalFlags(regex);
        regex = removeAnnotationByFlagX(regex);
        regex = processLocalFlag(regex);
        regex = replaceLocalFlagGM(regex);
        // 去group name
        regex = deleteGroupName(regex);

        // 建树
        TreeNode newlyttree = createReDoSTree(regex);

        // 将方括号中的\0~\777重写为\u0000~\u0777
        newlyttree.rewriteUnicodeNumberInBracketNode();

        // 将方括号中的\b删除 因为方括号中的\b表示退格符
        newlyttree.reWriteBackspace();

        // 转换[\w-.] -> [\w\-.] 而 [a-z]保留 为了regexlib
        newlyttree.rewriteIllegalBarSymbol();

        newlyttree = refactorAssertPattern(newlyttree);

        // 处理\x{....} \xff
        newlyttree.escapeHexadecimal();
        // 删除Flags
        newlyttree = getNodeByRemoveRegExpFlag(newlyttree);

        newlyttree = getNodeByRemoveLocalFlag(newlyttree);

        // 使用重写后的去首尾^$
        newlyttree.deleteCaretAndDollarSymbols();

//        regex = rewriteEmptyString(newlyttree.getData());
//
//        if (!regex.equals(newlyttree.getData())) {
//            newlyttree = createnewlyttree(regex);
//        }

        // 新版重写空串
        newlyttree = removeBlankStr(newlyttree);

        // 重写反向引用
        newlyttree.rewriteBackreferences();

        // 重写反向引用后 删除NonCapturingGroupFlag ?:
        newlyttree.deleteNonCapturingGroupFlag();

        // 获取后缀
//        String suffix = getSuffixByNegateNode(newlyttree);
        // 去补
        removeNegateSymbol(newlyttree, Constant.SimplyLevel.HIGH);

//        newlyttree = refactorToDot(newlyttree);

//        newlyttree = removeGroup(newlyttree);

//        return new Pair<>(newlyttree, suffix);

        // 计算所有结点的first last followLast nullable flexible
        newlyttree.calculateFiveAttributesNullableAndFirstAndLastAndFlexibleAndFollowLast();

        return newlyttree;
    }


    public static int getCounting(String regex1, String regex2, String firstCharacter) throws InterruptedException {
//        String regex = reWriteMetaEscape("(" + regex1 + regex2 + ")");
//        if (isSpecialStringNeedAddSquareBracketsForDkBricsAutomaton(firstCharacter)) firstCharacter = "[" + firstCharacter + "]";
//        regex = "(" + regex + ")＆(" + firstCharacter + ".*)";
//        regex = reductSpecailStringForDkBricsAutomaton(regex);
////        System.out.println(regex);
//        RegExp regExp = new RegExp(regex);
//        Automaton automaton = regExp.toAutomaton(false);
////        System.out.println(automaton.getCommonPrefix());
////        System.out.println(automaton.getShortestExample(true).length());
//        String str = automaton.getShortestExample(true);
//        return (str == null) ? 0 : str.length();


        // .*要转义的
        List<String> regexList1 = new ArrayList<>();
        regexList1.add(regex1 + regex2);

        // 先判断是否接受空串 b*b{0,1} 的counting应该是0 然后外面+1 b就可以攻击成功 如果再交上b.*反而会counting = 1 外面+1后生成bb,错误
        Automaton automaton = getIntersectionAutomaton(regexList1, null, 0);
        if (isAcceptEmptyString(automaton)) return 0;

        // .*不转义的
        List<String> regexList2 = new ArrayList<>();
        regexList2.add(firstCharacter + ".*");
        String str = getExampleByDkBricsAutomaton(regexList1, regexList2, 0);
        return (str == null) ? 0 : str.length();
    }

    // 生成中缀串forEOA
    private static String generateInfixStringForEOA(String regex0, String regex1, String regex2, String regex3, String regex4, int model, int counting) throws InterruptedException {
        String regex = "1&2";
        if (model == 1) {
            String infix1 = getExampleByDkBricsAutomaton(new ArrayList<>(Collections.singleton(regex0)));
            if (infix1 == null) return null;

            String infix2 = getExampleByDkBricsAutomaton(new ArrayList<>(Arrays.asList(regex1, regex3)), null, counting);
            if (infix2 == null) return null;

            String infix3 = getExampleByDkBricsAutomaton(new ArrayList<>(Collections.singleton(regex4)), null, 0);
            if (infix3 == null) return null;

            return infix1 + infix2 + infix3;


//            regex0 = reWriteMetaEscape(regex0);
//            RegExp regExp = new RegExp(regex0);
//            Automaton automaton = regExp.toAutomaton(false);
//            String infix1 = automaton.getShortestExample(true);
//
//            if (infix1 == null) return null;
//
//            regex = reWriteMetaEscape("(" + regex1 + ")＆(" + regex3 + ")") + "＆(.{" + counting + "})";
//            regex = reductSpecailStringForDkBricsAutomaton(regex);
//            regExp = new RegExp(regex);
//            automaton = regExp.toAutomaton(false);    // 这里要加第二个参数minimize: false 这样就是nfa了 比dfa快
//            String infix2 = automaton.getShortestExample(true);
//
//            if (infix2 == null) return null;
//
//            regex4 = reWriteMetaEscape(regex4);
//            regExp = new RegExp(regex4);
//            automaton = regExp.toAutomaton(false);
//            String infix3 = automaton.getShortestExample(true);
//
//            if (infix3 == null) return null;
//
//            return infix1 + infix2 + infix3;
        } else if (model == 2) {
            String infix2 = getExampleByDkBricsAutomaton(new ArrayList<>(Collections.singleton(regex2)));
            if (infix2 == null) return null;

            String infix1 = getExampleByDkBricsAutomaton(new ArrayList<>(Arrays.asList(regex1, regex3)), null, counting);
            if (infix1 == null) return null;

            return infix1 + infix2;

//            regex2 = reWriteMetaEscape(regex2);
//            RegExp regExp = new RegExp(regex2);
//            Automaton automaton = regExp.toAutomaton(false);
//            String infix2 = automaton.getShortestExample(true);
//
//            if (infix2 == null) return null;

//            regex = reWriteMetaEscape("(" + regex1 + ")＆(" + regex3 + ")") + "＆(.{" + counting + "})";
//            regex = reductSpecailStringForDkBricsAutomaton(regex);
//            regExp = new RegExp(regex);
//            automaton = regExp.toAutomaton(false);
//            String infix1 = automaton.getShortestExample(true);
//
//            if (infix1 == null) return null;
//
//            return infix1 + infix2;
        }
        return null;
    }

    private static String judgeThirdCondition(String beta1, String beta2, String nodeCounting, int beta1Nullable, int beta2Nullable) throws InterruptedException {
        if (beta1Nullable != 1 && beta2Nullable != 1) return "";

        List<String> regexList1 = new ArrayList<>();
        regexList1.add("(" + beta1 + ")" + nodeCounting);
        regexList1.add("(" + beta2 + ")" + nodeCounting);
        String infix = getExampleByDkBricsAutomaton(regexList1);
        return infix != null ? infix : "";


////        System.out.println(beta1);
////        System.out.println(beta2);
//        String regex = reWriteMetaEscape("((" + beta1 + ")" + nodeCounting + ")＆((" + beta2 + ")" + nodeCounting + ")");
//        regex = regex + "&(.+)";
//        regex = reductSpecailStringForDkBricsAutomaton(regex);
////        System.out.println(regex);
//        RegExp regExp = new RegExp(regex);
//        Automaton automaton = regExp.toAutomaton(false);
//        String infix = automaton.getShortestExample(true);
//        return infix != null ? infix : "";
    }

    private static String judgeFourthCondition(String beta1, String beta2, int beta1Nullable, int beta2Nullable) throws InterruptedException {
        if (beta1Nullable == 1 || beta2Nullable == 1) return "";

        List<String> regexList1 = new ArrayList<>();
        regexList1.add(beta1);
        regexList1.add(beta2);
        String infix = getExampleByDkBricsAutomaton(regexList1);
        return infix != null ? infix : "";


//        String regex = reWriteMetaEscape("(" + beta1 + ")＆(" + beta2 +")");
//        regex = regex + "&(.+)";
//        regex = reductSpecailStringForDkBricsAutomaton(regex);
////        System.out.println(regex);
//        RegExp regExp = new RegExp(regex);
//        Automaton automaton = regExp.toAutomaton(false);
//        String infix = automaton.getShortestExample(true);
//        return infix != null ? infix : "";
    }



    private static ReDoSBean getEOARedosBeanHelper(TreeNode root, String regex) throws InterruptedException {
        ReDoSBean bean = new ReDoSBean();
        ArrayList<AttackBean> attackBeanList = new ArrayList<>();
        Stack<TreeNode> stack = new Stack<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            TreeNode node = stack.pop();
            node = getGroupSubNode(node);
            if (isInBrackets(node)) continue;
            TreeNode specialParent = getTheNearestParentWithMaxNumGreaterThanOneGeneralizedCounting(node);
            if (specialParent != null) {
                node = getGroupSubNode(node);

                String nodeCounting = specialParent.getChild(1).getData();
                // 这里做个优化 {2,256} 这种直接改写为{2,}
                if (nodeCounting.contains(",")) {
                    nodeCounting = "{" + getCountingFirstNum(nodeCounting) + ",}";
                }

//                node = node.getChild(0);
//                node = getGroupSubNode(node);

                if (! isOrNode(node) && ! isGeneralizedCountingNode(node) && ! isBracketsNode(node) && ! node.isLeaf() && ! isGroupNode(node) && node.getChildCount() >= 2) {
                    List<TreeNode> childList = node.getChildList();
                    // 分割
                    for (int i = 0; i < childList.size() - 1; i++) {
                        // nullable
                        // 若为连接结点 则对其所有的孩子结点 跳过无效值 求并集 若并集中含有false 则为false 否则为true

                        // first
                        // 若为连接结点 对其所有的孩子结点 从左到右找到第一个nullable为false的孩子 则包括该孩子在内的 前面所有的孩子的first求并集
                        //                                若找不到 则把所有的孩子的first集求并集

                        // followLast
                        // 若为连接结点 否则从右往左找到第一个nullable为false的结点 若存在 记为child(i) 最后一个孩子结点记为child(n)
                        //            该结点的followLast为 getChild(i).getFollowLast() ∪ ... ∪ getChild(n).getFollowLast() ∪ getChild(i+1).getFirst() ∪ ... ∪ getChild(n).getFirst()
                        //                               若不存在 则上式中i = 0 依然成立

                        StringBuilder beta1 = new StringBuilder();
                        StringBuilder beta2 = new StringBuilder();
                        int beta1Nullable = 1;
                        int beta2Nullable = 1;
                        Set<String> beta1FirstSet = new HashSet<>();
                        Set<String> beta2FirstSet = new HashSet<>();
                        boolean beta1FirstNullableIsFalse = true;
                        boolean beta2FirstNullableIsFalse = true;
                        Set<String> beta1FollowLastSet = new HashSet<>();
                        Set<String> beta2FollowLastSet = new HashSet<>();

                        for (int j = 0; j < childList.size(); j++) {
                            if (j <= i) {
                                beta1.append(childList.get(j).getData());
                                // nullable
                                if (beta1Nullable == 1 && beta1Nullable != -1) beta1Nullable = childList.get(j).getNullable();
                                if (beta1FirstNullableIsFalse && beta1Nullable == 1) {
                                    beta1FirstSet.addAll(childList.get(j).getFirst());
                                } else if (beta1FirstNullableIsFalse && beta1Nullable == 0) {
                                    beta1FirstSet.addAll(childList.get(j).getFirst());
                                    beta1FirstNullableIsFalse = false;
                                }

                            } else {
                                beta2.append(childList.get(j).getData());
                                // nullable
                                if (beta2Nullable == 1 && beta2Nullable != -1) beta2Nullable = childList.get(j).getNullable();
                                if (beta2FirstNullableIsFalse && beta2Nullable == 1) {
                                    beta2FirstSet.addAll(childList.get(j).getFirst());
                                } else if (beta2FirstNullableIsFalse && beta2Nullable == 0) {
                                    beta2FirstSet.addAll(childList.get(j).getFirst());
                                    beta2FirstNullableIsFalse = false;
                                }
                            }
                        }

                        int j = i;
                        for (;  j >= 0 ; j--) {
                            if (node.getChild(j).getNullable() == 0) break;
                        }
                        if (j == -1) j = 0; // 修复索引超限
                        beta1FollowLastSet.addAll(node.getChild(j).getFollowLast());
                        j += 1;
                        for (; j <= i; j++) {
                            beta1FollowLastSet.addAll(node.getChild(j).getFollowLast());
                            beta1FollowLastSet.addAll(node.getChild(j).getFirst());
                        }

                        j = node.getChildCount() - 1;
                        for (;  j > i ; j--) {
                            if (node.getChild(j).getNullable() == 0) break;
                        }
                        if (j == -1) j = 0; // 修复索引超限
                        beta2FollowLastSet.addAll(node.getChild(j).getFollowLast());
                        j += 1;
                        for (; j < node.getChildCount(); j++) {
                            beta2FollowLastSet.addAll(node.getChild(j).getFollowLast());
                            beta2FollowLastSet.addAll(node.getChild(j).getFirst());
                        }

                        if (!Collections.disjoint(beta1FollowLastSet, beta2FirstSet)) {
                            Set<String> intersection = new HashSet<>();    // 交集
                            intersection.addAll(beta1FollowLastSet);
                            intersection.retainAll(beta2FirstSet);
                            String firstCharacter = intersection.iterator().next();  // 获取第一个元素

                            // 反着找是是谁产生的followLast和first
                            String regex0 = ""; // 产生followLast的前面的子正则
                            String regex1 = ""; // 产生followLast的子正则
                            String regex2 = ""; // 产生first的子正则
                            String regex3 = ""; // 产生first的后面的子正则
                            Set<String> regex1FollowLast = new HashSet<>(); // 动态记录产生followLast的子正则的followLast
                            int k1 = i, k2 = i + 1;
                            for (; k1 >= 0; k1--) {
                                if (! regex1FollowLast.containsAll(intersection)) {
                                    regex1FollowLast.addAll(childList.get(k1).getFollowLast());
                                    regex1 = childList.get(k1).getData() + regex1;
                                } else {
                                    break;
                                }
                            }

                            for (; k1 >= 0; k1--) {
                                regex0 = childList.get(k1).getData() + regex0;
                            }

                            for (; k2 < childList.size(); k2++) {
                                if (childList.get(k2).getFirst().containsAll(intersection)) {
                                    regex2 = regex2 + childList.get(k2).getData();
                                } else {
                                    break;
                                }
                            }

                            for (; k2 < childList.size(); k2++) {
                                regex3 = regex3 + childList.get(k2).getData();
                            }

//                            System.out.println(regex0 + " " + regex1 + " " + regex2 + " " + regex3);

                            int counting = getCounting(regex1, regex2, firstCharacter) + 1;
//                            System.out.println(counting);

//                            int counting = getCountingFirstNum(regex1) + getCountingFirstNum(regex2) + 1;
//                            System.out.println("counting = " + counting);

                            String infix = generateInfixStringForEOA(regex0, regex1, null, regex2, regex3, 1, counting);
                            if (infix != null) {
                                AttackBean attackBean = new AttackBean();
                                attackBean.setPrefix(root.getMatchStr(node));
                                attackBean.setInfix(infix);
                                attackBean.setSuffix(root.getNonMatchStr() + "_EOA(i)");
                                attackBean.initType(AttackType.EXPONENT);
//                                attackBean.setPatternType(PatternType.EOA);
//                                    attackBean.setConflictPoint(new Pair<>());
                                attackBeanList.add(attackBean);
                            }
                        }






                        if (!Collections.disjoint(beta1FirstSet, beta2FollowLastSet)) {
//                            System.out.println(beta1 + " " + beta2 + " " + beta1FirstSet + " " + beta2FollowLastSet);

                            Set<String> intersection = new HashSet<String>();    // 交集
                            intersection.addAll(beta1FirstSet);
                            intersection.retainAll(beta2FollowLastSet);
                            String firstCharacter = intersection.iterator().next();  // 获取第一个元素


                            // 反着找是是谁产生的first和followLast
                            String regex1 = ""; // 产生first的子正则
                            String regex2 = ""; // 产生followLast的子正则
                            String regex3 = ""; // 产生first的子正则到产生followLast的子正则中间的子正则
                            Set<String> regex2FollowLast = new HashSet<>(); // 动态记录产生followLast的子正则的followLast
                            int k1 = 0, k2 = childList.size() - 1;
                            for (; k1 <= i; k1++) {
                                if (childList.get(k1).getFirst().containsAll(intersection)) {
                                    regex1 = regex1 + childList.get(k1).getData();
                                } else {
                                    break;
                                }
                            }
                            for (; k2 > i; k2--) {
                                if (! regex2FollowLast.containsAll(intersection)) {
                                    regex2 = childList.get(k2).getData() + regex2;
                                } else {
                                    break;
                                }
                            }

                            for (int k = k1; k <= k2; k++) {
                                regex3 = regex3 + childList.get(k).getData();
                            }



                            int counting = getCounting(regex1, regex2, firstCharacter) + 1;
//                            System.out.println(regex1 + " " + regex2 + " " + regex3 + " " + counting);

                            String infix = generateInfixStringForEOA(null, regex1, regex3, regex2, null, 2, counting);
                            if (infix != null) {
                                AttackBean attackBean = new AttackBean();
                                attackBean.setPrefix(root.getMatchStr(node));
                                attackBean.setInfix(infix);
                                attackBean.setSuffix(root.getNonMatchStr() + "_EOA(ii)");
                                attackBean.initType(AttackType.EXPONENT);
//                                attackBean.setPatternType(PatternType.EOA);
//                                    attackBean.setConflictPoint(new Pair<>());
                                attackBeanList.add(attackBean);
                            }
                        }




                        String thirdConditionInfix = judgeThirdCondition(beta1.toString(), beta2.toString(), nodeCounting, beta1Nullable, beta2Nullable);
                        if (! thirdConditionInfix.equals("")) {
                            AttackBean attackBean = new AttackBean();
                            attackBean.setPrefix(root.getMatchStr(node));
                            attackBean.setInfix(thirdConditionInfix);
                            attackBean.setSuffix(root.getNonMatchStr() + "_EOA(iii)");
                            attackBean.initType(AttackType.EXPONENT);
//                            attackBean.setPatternType(PatternType.EOA);
//                                    attackBean.setConflictPoint(new Pair<>());
                            attackBeanList.add(attackBean);
                        }



                        String fourthConditionInfix = judgeFourthCondition(beta1.toString(), beta2.toString(), beta1Nullable, beta2Nullable);
                        if (! fourthConditionInfix.equals("")) {
                            AttackBean attackBean = new AttackBean();
                            attackBean.setPrefix(root.getMatchStr(node));
                            attackBean.setInfix(fourthConditionInfix);
                            attackBean.setSuffix(root.getNonMatchStr() + "_EOA(iv)");
                            attackBean.initType(AttackType.EXPONENT);
//                            attackBean.setPatternType(PatternType.EOA);
//                                    attackBean.setConflictPoint(new Pair<>());
                            attackBeanList.add(attackBean);
                        }
                    }

                }
            }
            for (int i = node.getChildCount() - 1; i >= 0; i--) {
                stack.push(node.getChild(i));
            }
        }
        if (attackBeanList.size() > 0) {
            bean.setAttackBeanList(attackBeanList);
            bean.setReDoS(true);
        } else {
            bean.setReDoS(false);
        }
        return bean;
    }


    public static ReDoSBean getEOARedosBean(String regex) {
        ReDoSBean bean = new ReDoSBean();
        try {
            TreeNode tree = getRedosTree(regex);
            bean = getEOARedosBeanHelper(tree, regex);
        } catch (InterruptedException e) {
            bean.setReDoS(false);
        } catch (Exception e) {
            System.out.println(regex);
            e.printStackTrace();
            bean.setMessage("PARSE ERROR");
            bean.setReDoS(false);
        }
        return bean;
    }

    public static void main(String[] args) throws InterruptedException {
        String regex = "xyz(bb|ab{3,5})+xyz(\\d\\.|\\d|\\.)+xyz(abcd|a|b|c|d)+";
        regex = "(.|\\n|\\s)+";
        regex = "(a*b?ab+)+";
        regex = "@Test\\s*\\(([^@\\n]*)\\)\\s+(@\\w+\\s*\\([^@\\n]*\\s*)*@CitrusTest\\(([^@\\n]*)\\)((?!(public|private|protected)).*\\s*)+(public|private|protected)\\s+((?!((description|}))).*\\s*)+(description\\s*\\(\\s*\\\"\\s*(.*)\\s*\\\"\\s*\\))?";
//        regex = "(ab*b{4,}b*c)+";
//        regex = "(a+b+a+)+";
        regex = "^(.+)\\s(\\/.*)\\?(.+=.+)+\\s(.+)\\/(\\d\\.\\d)$\\n(^(.+):\\s(.*)$\\n)*";
        regex = "^(?<azurePrefix>https:\\/\\/%%BLOBCONTAINER%%.blob.core.windows.net)\\/(?<containerId>\\S+)\\/(?<inDir>in)\\/(?<path>(\\S+\\/)*?)(?<filename>[^<>:\"/\\\\\\|\\?\\*]+(\\.[^<>:\"/\\\\\\|\\?\\*]+)*)$";
        regex = "(https:\\/\\/%%BLOBCONTAINER%%.blob.core.windows.net)\\/([\"%:<>*./?\\\\|!\\w]+)\\/(in)\\/(([\"%:<>*./?\\\\|!\\w]+\\/)*)([%.v!\\w\\s]+(\\.[%.v!\\w\\s]+)*)";
        regex = "(LEFT JOIN|JOIN) `([\\w\\{\\}$->]+)` (\\w+) ON (\\w+)\\.(\\w.+) = (\\w+)\\.(\\w.+)($)";
        regex = "(?i-mx:[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?!json|html|xml)(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)|(?i-mx:[a-z0-9\\-]*)";
        regex = ">([^<]+)[^[]+\\[([^\\]]+)]\\[([^\\]]+)]";
        regex = "[\",:<>\\-/v_!B-Za-z\\d\\s]*(?:ASM:|A.*ASM:).*\\s+ASM:\"([,:<>\\-/v!\\w\\s]+)\",\"(\\d+\\-\\d+\\-\\d+\\s+\\d+:\\d+:\\d+)\",\"(\\w+)\",\"([,:<>\\-/v!\\w\\s]*)\",\"([,:<>\\-/v!\\w\\s]*)\",\"(\\d+)\",\"([,:<>\\-/v!\\w\\s]+)\",\"([,:<>\\-/v!\\w\\s]+)\",\"([,:<>\\-/v!\\w\\s]+)\",\"([,:<>\\-/v!\\w\\s]+)\",\"([,:<>\\-/v!\\w\\s]+)\",\"([,:<>\\-/v!\\w\\s]+)\",\"([,:<>\\-/v!\\w\\s]+)\"(?:,\"([,:<>\\-/v!\\w\\s]+)\",\"(\\d+)\",\"([,:<>\\-/v!\\w\\s]+)\",\"([,:<>\\-/v!\\w\\s]+)\",\"([,:<>\\-/v!\\w\\s]*)\",\"([,:<>\\-/v!\\w\\s]+)\"(?:,\"([,:<>\\-/v!\\w\\s]+(<viol_name>.*<\\/viol_name>)+.*(<context>.*<\\/context>)*.*(<param_name_pattern>.*<\\/param_name_pattern>)*[,:<>\\-/v!\\w\\s]+))?)?";
        regex = "(\\n|\\r|\\t|\\0|^\\s+|\\s+$|[\\b])";
        regex = "^(((((((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?)|(((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?\"((\\s? +)?(([!#-[\\]-~])|(\\\\([ -~]|\\s))))*(\\s? +)?\"))?)?(((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?<(((((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?(([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+(\\.([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+)*)((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?)|(((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?\"((\\s? +)?(([!#-[\\]-~])|(\\\\([ -~]|\\s))))*(\\s? +)?\"))@((((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?(([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+(\\.([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+)*)((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?)|(((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?\\[((\\s? +)?([!-Z^-~]))*(\\s? +)?\\]((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?)))>((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?))|(((((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?(([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+(\\.([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+)*)((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?)|(((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?\"((\\s? +)?(([!#-[\\]-~])|(\\\\([ -~]|\\s))))*(\\s? +)?\"))@((((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?(([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+(\\.([A-Za-z0-9!#-'*+\\/=?^_`{|}~-])+)*)((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?)|(((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?\\[((\\s? +)?([!-Z^-~]))*(\\s? +)?\\]((((\\s? +)?(\\(((\\s? +)?(([!-'*-[\\]-~]*)|(\\\\([ -~]|\\s))))*(\\s? +)?\\)))(\\s? +)?)|(\\s? +))?))))$";
        regex = "\\b((((https?:\\/\\/)?([-a-zA-Z0-9@:%_\\+~#=]\\.?){2,256}(?<!\\.)\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%_\\+~#?&=//]\\.?)*)?(/?ark:/))|(info:ark/))(([-a-zA-Z0-9@:%_\\+~#?&=//]\\.?)+)(?<!\\.)";
        regex = "^([a-zA-Z0-9]+)(((\\.|#)([^ (]*))+)?\\(([^)]*)\\)(\\[([^\\]]*)\\])?";
        regex = "(a*a(a*|bc)bc)*d";
        regex = "(abc.+)+";
        regex = "((a*a*))*";
        regex = "(a*b?ab+)+";
        regex = "(a+b+a+)+";
        regex = "^(((aa{1,2})b?)c?)+$";
        regex = "((abc.+)|c)+";
//        regex = "(ab?b?)+";
//        regex = "(d?ab+b+c?)+";
//        regex = "((\\s)*[a-zA-Z](\\s)*)*";
//        regex = "^(ab*b{0,1})+";
//        regex = "(d?(ab+)b+c?)+";
//        regex = "^(ab*b*a)+";
        regex = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[&-+!*$@%_])([&-+!*$@%_\\w]{8,15})$";
        regex = "^(\\s*([,;]|$)+\\s*)*$";
        TreeNode newlyttree = getRedosTree(regex);
        newlyttree.rewriteIllegalBarSymbol();
        printTree(newlyttree);
//        System.out.println(getOrSymbolTreeNode(newlyttree.getChild(0)));
        ReDoSBean reDosBean = getEOARedosBean(regex);
        ArrayList<AttackBean> attackBeanList = reDosBean.getAttackBeanList();
        for (int i = 0; i < attackBeanList.size(); i++) {
            System.out.println(attackBeanList.get(i).getAttackStringFormat());
        }
    }
}
