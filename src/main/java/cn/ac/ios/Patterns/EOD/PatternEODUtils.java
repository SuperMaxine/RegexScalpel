package cn.ac.ios.Patterns.EOD;

import cn.ac.ios.TreeNode.TreeNode;
import cn.ac.ios.Bean.*;
import cn.ac.ios.Utils.Constant;

import java.util.*;

import static cn.ac.ios.TreeNode.Utils.*;
import static cn.ac.ios.Utils.DkBricsAutomatonUtils.*;
import static cn.ac.ios.Utils.FlagsUtils.*;
import static cn.ac.ios.Utils.FlagsUtils.getNodeByRemoveLocalFlag;
import static cn.ac.ios.Utils.NegateUtils.refactorAssertPattern;
import static cn.ac.ios.Utils.NegateUtils.removeNegateSymbol;
import static cn.ac.ios.Utils.RegexUtils.*;

public class PatternEODUtils {
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

        // 重写反向引用
        newlyttree.rewriteBackreferences();

        // 获取后缀
//        String suffix = getSuffixByNegateNode(newlyttree);
        // 去补
        removeNegateSymbol(newlyttree, Constant.SimplyLevel.HIGH);

        // 新版重写空串
        newlyttree = removeBlankStr(newlyttree);

        // 重写反向引用后 删除NonCapturingGroupFlag ?:
        newlyttree.deleteNonCapturingGroupFlag();

//        newlyttree = refactorToDot(newlyttree);

//        newlyttree = removeGroup(newlyttree);

//        return new Pair<>(newlyttree, suffix);

        // 计算所有结点的first last followLast nullable flexible
        newlyttree.calculateFiveAttributesNullableAndFirstAndLastAndFlexibleAndFollowLast();

        return newlyttree;
    }


    // 生成中缀串forEOD
    private static String generateInfixStringForEOD(String regex1, String regex2, int model, String firstCharacter) throws InterruptedException {
        if (model == 1) {
            List<String> regexList1 = new ArrayList<>();
            regexList1.add("(" + regex1 + ")+(" + regex2 + ")+");
            regexList1.add("(" + regex1 + ")+");
            List<String> regexList2 = new ArrayList<>();
            regexList2.add(firstCharacter + ".*");
            return getExampleByDkBricsAutomaton(regexList1, regexList2);
        } else if (model == 2) {
            List<String> regexList1 = new ArrayList<>();
            regexList1.add("(" + regex1 + ")+(" + regex2 + ")+");
            regexList1.add("(" + regex2 + ")+");
            List<String> regexList2 = new ArrayList<>();
            regexList2.add(firstCharacter + ".*");
            return getExampleByDkBricsAutomaton(regexList1, regexList2);
        } else if (model == 3) {
            List<String> regexList1 = new ArrayList<>();
            regexList1.add("(" + regex2 + ")+(" + regex1 + ")+");
            regexList1.add("(" + regex1 + ")+");
            List<String> regexList2 = new ArrayList<>();
            regexList2.add(firstCharacter + ".*");
            return getExampleByDkBricsAutomaton(regexList1, regexList2);
        } else if (model == 4) {
            List<String> regexList1 = new ArrayList<>();
            regexList1.add("(" + regex2 + ")+(" + regex1 + ")+");
            regexList1.add("(" + regex2 + ")+");
            List<String> regexList2 = new ArrayList<>();
            regexList2.add(firstCharacter + ".*");
            return getExampleByDkBricsAutomaton(regexList1, regexList2);
        } else if (model == 5) {
            List<String> regexList1 = new ArrayList<>();
            regexList1.add(regex2 + regex1);
            List<String> regexList2 = new ArrayList<>();
            regexList2.add(regex2 + ".*");
            return getExampleByDkBricsAutomaton(regexList1, regexList2);
        }
        return null;



//        String regex = "1&2";
//
//        if (isSpecialStringNeedAddSquareBracketsForDkBricsAutomaton(firstCharacter)) { firstCharacter = "[" + firstCharacter + "]"; }
//
//        if (model == 1) {
//            regex = "(" + regex1 + ")+(" + regex2 + ")+&(" + regex1 + ")+&(" + firstCharacter + ").*";
//        } else if (model == 2) {
//            regex = "(" + regex1 + ")+(" + regex2 + ")+&(" + regex2 + ")+&(" + firstCharacter + ").*";
//        } else if (model == 3) {
//            regex = "(" + regex2 + ")+(" + regex1 + ")+&(" + regex1 + ")+&(" + firstCharacter + ").*";
//        } else if (model == 4) {
//            regex = "(" + regex2 + ")+(" + regex1 + ")+&(" + regex2 + ")+&(" + firstCharacter + ").*";
//        } else if (model == 5) {
//            regex = regex2 + regex1 + "&" + regex2 + ".+";
//        }
//
//
////        regex = "1&2";
//
////        System.out.println(regex);
////        System.exit(0);
//
//        RegExp regExp = new RegExp(regex);
//        Automaton automaton = regExp.toAutomaton(false);    // 这里要加第二个参数minimize: false 这样就是nfa了 比dfa快
////        String infix = automaton.getShortestExample(true);
////        infix = Objects.equals(infix, null) ? "null" : infix;
////        return infix;
//        return automaton.getShortestExample(true);
    }

//    // 重载generateInfixStringForEOD 输入参数为TreeNode
//    private static String generateInfixStringForEOD(TreeNode treeNode1, TreeNode treeNode2, int model, String firstCharacter) throws InterruptedException {
//        return generateInfixStringForEOD(reWriteMetaEscape(treeNode1), reWriteMetaEscape(treeNode2), model, firstCharacter);
//    }




        // 找需要排除的r前后的|
    private static TreeNode getOrSymbolTreeNode(TreeNode treeNode) {
        if (treeNode.isFirstChild()) {
            if (treeNode.getNextNode().getData().equals("|")) return treeNode.getNextNode();
            else return null;
        } else if (treeNode.isLastChild()) {
            if (treeNode.getPreviousNode().getData().equals("|")) return treeNode.getPreviousNode();
            else return null;
        } else {
            if (treeNode.getPreviousNode().getData().equals("|")) return treeNode.getPreviousNode();
            else if (treeNode.getNextNode().getData().equals("|")) return treeNode.getNextNode();
        }
        return null;
    }


    private static ReDoSBean getEODRedosBeanHelper(TreeNode root, String regex) throws InterruptedException {
        ReDoSBean bean = new ReDoSBean();
        ArrayList<AttackBean> attackBeanList = new ArrayList<>();
        Stack<TreeNode> stack = new Stack<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            TreeNode node = stack.pop();
            if (isGeneralizedCountingNodeWithMaxNumGreaterThanOne(node)) {
                node = getGroupSubNode(node);
                node = node.getChild(0);
                node = getGroupSubNode(node);

                if (isOrNode(node)) {
                    for (int i = 0; i < node.getChildCount() - 2; i += 2) {
                        for (int j = i + 2; j < node.getChildCount(); j++) {
                            if (!Collections.disjoint(node.getChild(i).getFirst(), node.getChild(j).getFirst())) {
                                // 对于r = (r1|r2|...|rn)+ 如果r1 r2有歧义
                                // 如果是r1.first ∩ r2.first ≠ ∅ 中缀w = (r1|r3|...|rn)+ (r2|...|rn)+ & (r1|r3|...|rn)+ & firstCharacter .*
                                //                                  w = (r1|r3|...|rn)+ (r2|...|rn)+ & (r2|r3|...|rn)+ & firstCharacter .*
                                //                                  w = (r2|r3|...|rn)+ (r1|r3|...|rn)+ & (r2|r3|...|rn)+ & firstCharacter .*
                                //                                  w = (r2|r3|...|rn)+ (r1|r3|...|rn)+ & (r2|r3|...|rn)+ & firstCharacter .*


                                Set<String> intersection = new HashSet<String>();    // 交集
                                intersection.addAll(node.getChild(i).getFirst());
                                intersection.retainAll(node.getChild(j).getFirst());
                                String firstCharacter = intersection.iterator().next();  // 获取第一个元素
                                // 需要对\f \n \r \t
                                if (firstCharacter.equals("\\t")) {
                                    firstCharacter = "\t";
                                } else if (firstCharacter.equals("\\f")) {
                                    firstCharacter = "\f";
                                } else if (firstCharacter.equals("\\n")) {
                                    firstCharacter = "\n";
                                } else if (firstCharacter.equals("\\v") || firstCharacter.equals("\\u000b")) {
                                    firstCharacter = "\u000b";
                                }

                                // 找需要排除的r前后的|

//                                System.out.println(node.getData());
//                                System.out.println(node.getChild(i).getData());
//                                System.out.println(getOrSymbolTreeNode(node.getChild(i)).getData());
                                String regex1n = reWriteMetaEscapeForEODInfix(node, node.getChild(i), getOrSymbolTreeNode(node.getChild(i))); // 除掉r2
                                String regex2n = reWriteMetaEscapeForEODInfix(node, node.getChild(j), getOrSymbolTreeNode(node.getChild(j)));  // 除掉r1
//                                System.out.println("node = " + node.getData());
//                                System.out.println("node.getChild(i) = " + node.getChild(i).getData());
//                                System.out.println("node.getChild(j) = " + node.getChild(j).getData());
//                                System.out.println("regex1n = " + regex1n);
//                                System.out.println("regex2n = " + regex2n);

//                                System.out.println(1);
                                String infix = generateInfixStringForEOD(regex1n, regex2n, 1, firstCharacter);
                                if (infix != null) {
                                    AttackBean attackBean = new AttackBean();
                                    attackBean.setPrefix(root.getMatchStr(node.getChild(i)));
                                    attackBean.setInfix(infix);
                                    attackBean.setSuffix(root.getNonMatchStr() + "_EOD(i1)");
                                    attackBean.initType(AttackType.EXPONENT);
//                                    attackBean.setPatternType(PatternType.EOD);
//                                    attackBean.setConflictPoint(new Pair<>());
                                    attackBeanList.add(attackBean);
                                }

//                                System.out.println(2);
                                infix = generateInfixStringForEOD(regex1n, regex2n, 2, firstCharacter);
                                if (infix != null) {
                                    AttackBean attackBean = new AttackBean();
                                    attackBean.setPrefix(root.getMatchStr(node.getChild(i)));
                                    attackBean.setInfix(infix);
                                    attackBean.setSuffix(root.getNonMatchStr() + "_EOD(i2)");
                                    attackBean.initType(AttackType.EXPONENT);
//                                    attackBean.setPatternType(PatternType.EOD);
//                                    attackBean.setConflictPoint(new Pair<>());
                                    attackBeanList.add(attackBean);
                                }

//                                System.out.println(3);
                                infix = generateInfixStringForEOD(regex1n, regex2n, 3, firstCharacter);
                                if (infix != null) {
                                    AttackBean attackBean = new AttackBean();
                                    attackBean.setPrefix(root.getMatchStr(node.getChild(i)));
                                    attackBean.setInfix(infix);
                                    attackBean.setSuffix(root.getNonMatchStr() + "_EOD(i3)");
                                    attackBean.initType(AttackType.EXPONENT);
//                                    attackBean.setPatternType(PatternType.EOD);
//                                    attackBean.setConflictPoint(new Pair<>());
                                    attackBeanList.add(attackBean);
                                }

//                                System.out.println(4);
                                infix = generateInfixStringForEOD(regex1n, regex2n, 4, firstCharacter);
                                if (infix != null) {
                                    AttackBean attackBean = new AttackBean();
                                    attackBean.setPrefix(root.getMatchStr(node.getChild(i)));
                                    attackBean.setInfix(infix);
                                    attackBean.setSuffix(root.getNonMatchStr() + "_EOD(i4)");
                                    attackBean.initType(AttackType.EXPONENT);
//                                    attackBean.setPatternType(PatternType.EOD);
//                                    attackBean.setConflictPoint(new Pair<>());
                                    attackBeanList.add(attackBean);
                                }
                            }

                            // 如果是r1.first ∩ r2.followLast ≠ ∅ 中缀w = r2r1&r2
                            if (!Collections.disjoint(node.getChild(i).getFirst(), node.getChild(j).getFollowLast())) {
                                // 通过拼接生成攻击串 node.getChild(j).getData() + node.getChild(i).getData()
//                                System.out.println(generateInfixStringForEOD(node.getChild(i).getData(), node.getChild(j).getData(), 2));
//                                System.out.println(node.getChild(j).getData() + node.getChild(i).getData() + " EOD(ii)");

                                String infix = generateInfixStringForEOD(node.getChild(i).getData(), node.getChild(j).getData(), 5, "");
                                if (infix != null) {
                                    AttackBean attackBean = new AttackBean();
                                    attackBean.setPrefix(root.getMatchStr(node.getChild(i)));
                                    attackBean.setInfix(infix);
                                    attackBean.setSuffix(root.getNonMatchStr() + "_EOD(ii1)");
                                    attackBean.initType(AttackType.EXPONENT);
//                                    attackBean.setPatternType(PatternType.EOD);
//                                attackBean.setConflictPoint(new Pair<>());
                                    attackBeanList.add(attackBean);
                                }
                            }

                            if (!Collections.disjoint(node.getChild(j).getFirst(), node.getChild(i).getFollowLast())) {
                                // 通过拼接生成攻击串 node.getChild(i).getData() + node.getChild(j).getData()
//                                System.out.println(generateInfixStringForEOD(node.getChild(j).getData(), node.getChild(i).getData(), 2));
//                                System.out.println(node.getChild(i).getData() + node.getChild(j).getData() + " EOD(iii)");

                                String infix = generateInfixStringForEOD(node.getChild(j).getData(), node.getChild(i).getData(), 5, "");
                                if (infix != null) {
                                    AttackBean attackBean = new AttackBean();
                                    attackBean.setPrefix(root.getMatchStr(node.getChild(i)));
                                    attackBean.setInfix(infix);
                                    attackBean.setSuffix(root.getNonMatchStr() + "_EOD(ii2)");
                                    attackBean.initType(AttackType.EXPONENT);
//                                    attackBean.setPatternType(PatternType.EOD);
//                                attackBean.setConflictPoint(new Pair<>());
                                    attackBeanList.add(attackBean);
                                }
                            }
                        }
                    }
                }

//                ArrayList<TreeNode> allGeneralizedCountingNode = node.getAllGeneralizedCountingWithMaxNumLeqOneNode();
//                for (TreeNode generalizedCountingNode: allGeneralizedCountingNode) {
//                    if (node == generalizedCountingNode) continue;
//
//                    // 要求counting {m,n}中 m ≠ n
//                    if (isEqualCountingNode(generalizedCountingNode)) continue;
//
//                    if (judgeInNodeOneAllNodesExceptNodeTwoCanEmpty(node, generalizedCountingNode)) {
//                        AttackBean attackBean = new AttackBean();
//                        attackBean.setPrefix(root.getMatchStr(generalizedCountingNode));
//                        attackBean.setRepeat(generalizedCountingNode.getMatchStrWithCounting());
//                        attackBean.setSuffix(root.getNonMatchStr() + "_EOD(i)");
//                        attackBean.initType(AttackType.EXPONENT);
//                        attackBeanList.add(attackBean);
//                    }
//                }
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


    public static ReDoSBean getEODRedosBean(String regex) {
        ReDoSBean bean = new ReDoSBean();
        try {
            TreeNode tree = getRedosTree(regex);
            bean = getEODRedosBeanHelper(tree, regex);
        } catch (InterruptedException e) {
            bean.setReDoS(false);
        } catch (Exception e) {
//            System.out.println(regex);
//            e.printStackTrace();
            bean.setMessage("PARSE ERROR");
            bean.setReDoS(false);
        }
        return bean;
    }

    public static void main(String[] args) throws InterruptedException {
        String regex = "xyz(bb|ab{3,5})+xyz(\\d\\.|\\d|\\.)+xyz(abcd|a|b|c|d)+";
        regex = "(.|\\n|\\s)+";
        regex = "(\\s*<script.*>)((\\s|.)*)(<\\/script\\s*?>)";
//        regex = "^\\[\\s*(((-?([_a-z]|(?![\\u0000-\\u0239]).*|((\\\\[0-9a-f]{1,6}(\\r\\n|[ \\t\\r\\n\\f])?)|\\\\[^\\r\\n\\f0-9a-f]))([_a-z0-9-]|(?![\\u0000-\\u0239]).*|((\\\\[0-9a-f]{1,6}(\\r\\n|[ \\t\\r\\n\\f])?)|\\\\[^\\r\\n\\f0-9a-f]))*)|\\\\*)?|)?(-?([_a-z]|(?![\\u0000-\\u0239]).*|((\\\\[0-9a-f]{1,6}(\\r\\n|[ \\t\\r\\n\\f])?)|\\\\[^\\r\\n\\f0-9a-f]))([_a-z0-9-]|(?![\\u0000-\\u0239]).*|((\\\\[0-9a-f]{1,6}(\\r\\n|[ \\t\\r\\n\\f])?)|\\\\[^\\r\\n\\f0-9a-f]))*)\\s*((\\^=|\\$=|\\*=|=|~=|\\|=)\\s*((-?([_a-z]|(?![\\u0000-\\u0239]).*|((\\\\[0-9a-f]{1,6}(\\r\\n|[ \\t\\r\\n\\f])?)|\\\\[^\\r\\n\\f0-9a-f]))([_a-z0-9-]|(?![\\u0000-\\u0239]).*|((\\\\[0-9a-f]{1,6}(\\r\\n|[ \\t\\r\\n\\f])?)|\\\\[^\\r\\n\\f0-9a-f]))*)|((\\\"([^\\n\\r\\f\\\"]|\\\\n|\\r\\n|\\r|\\f|(?![\\u0000-\\u0239]).*|((\\\\[0-9a-f]{1,6}(\\r\\n|[ \\t\\r\\n\\f])?)|\\\\[^\\r\\n\\f0-9a-f]))*\\\")|(\\'([^\\n\\r\\f\\']|\\\\n|\\r\\n|\\r|\\f|(?![\\u0000-\\u0239]).*|((\\\\[0-9a-f]{1,6}(\\r\\n|[ \\t\\r\\n\\f])?)|\\\\[^\\r\\n\\f0-9a-f]))*\\')))\\s*)?\\]$";
        regex = "(\\/\\*([^*]|[\\r\\n]|(\\*+([^*\\/]|[\\r\\n])))*\\*+\\/)|(\\/\\/.*)";
        regex = "(?<lat0>\\d+)[-|\\s](?<lat1>\\d+)[.|,|\\s](?<lat2>\\d+)['|\\s]?(?<latDir>[N|n|S|s])[,|\\s|\\-|–]+(?<lon0>\\d+)[-|\\s](?<lon1>\\d+)[.|,|\\s](?<lon2>\\d+)['|\\s]?(?<lonDir>[E|e|W|w])";
        regex = "(\\d+)[-|\\s](\\d+)[.|,|\\s](\\d+)['|\\s]?([N|n|S|s])[,|\\s|\\-|–]+(\\d+)[-|\\s](\\d+)[.|,|\\s](\\d+)['|\\s]?([E|e|W|w])";
        regex = "(^[xX][= \\0]{0,2})(a\\d{3,7}|a\\d{2,6})+";
//        regex = "^(\\-)?(?:(\\d*)[. ])?(\\d+)\\:(\\d+)(?:\\:(\\d+)\\.?(\\d{3})?\\d*)?$";
        regex = "(abc|a|b|c)*";
//        regex = "^(([ab]|[bc])e?)*";
        regex = "(ab?|b)+";
        TreeNode newlyttree = getRedosTree(regex);
        printTree(newlyttree);
//        RegExp regExp = new RegExp(newlyttree.getData());
//        Automaton automaton = regExp.toAutomaton(false);
//        System.out.println(automaton.getShortestExample(true));
//        System.exit(0);
        ReDoSBean reDosBean = getEODRedosBean(regex);
        ArrayList<AttackBean> attackBeanList = reDosBean.getAttackBeanList();
        for (int i = 0; i < attackBeanList.size(); i++) {
            System.out.println(attackBeanList.get(i).getAttackStringFormat());
        }
    }
}
