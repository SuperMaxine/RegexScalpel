package cn.ac.ios;


import cn.ac.ios.TreeNode.TreeNode;

import static cn.ac.ios.Patterns.NQ.PatternNQUtils.getReDoSTree;
import static cn.ac.ios.Patterns.NQ.PatternNQUtils.getStandardizedReDoSTree;
import static cn.ac.ios.TreeNode.Utils.*;
import static cn.ac.ios.TreeNode.Utils.setInitialChainIndex;
import static cn.ac.ios.Utils.FlagsUtils.*;
import static cn.ac.ios.Utils.FlagsUtils.replaceLocalFlagGM;

public class PreprocessingInterface {
    public static String preprocess(String regex) {
        try {
            TreeNode sourceReDoSTree = getReDoSTree(regex, "java");
            // regex = ReDoSTreeToRegex(sourceReDoSTree);
            TreeNode standardizedReDoSTree = getStandardizedReDoSTree(sourceReDoSTree, "java");
            regex = ReDoSTreeToRegex(standardizedReDoSTree);

            // System.out.println("ReDoSTreeToRegex: " + regex);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return regex;
    }
}
