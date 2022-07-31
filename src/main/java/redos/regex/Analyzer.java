package redos.regex;

import com.alibaba.fastjson.JSONObject;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import redos.regex.redosPattern.Branch;
import redos.regex.redosPattern.Node;
import redos.regex.redosPattern.Ques;
import redos.utils.PatternUtils;

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;

public class Analyzer {
    redosPattern pattern;
    Pattern4Search pattern4Search;
    int maxLength;

    boolean possible_vulnerability;

    Vector<Vector<Node>> loopInLoop;
    Vector<Vector<Node>> branchInLoop;
    Vector<Vector<Node>> loopAfterLoop;
    Set<Node> loopNodes;

    Vector<VulStructure> possibleVuls;

    String regex;

    private class finalVul {
        VulType type;
        VulStructure vul;
        VulStructure vul2;
        Vector<Set<Integer>> infix;
        StringBuffer prefix;
        StringBuffer pump;
        StringBuffer suffix;

        // 以下内容是为了获取正确的后缀所建立
        Node suffixHead;
        VulStructure getSuffix;
        Vector<Set<Integer>> correctSuffix;

        // 为了优化②
        Vector<Set<Integer>> suffixSets;
        finalVul(VulStructure newVul, VulType vulType){
            type = vulType;
            vul = newVul;
            infix = new Vector<>();

            prefix = newVul.prefix;
            suffix = newVul.suffix;

            suffixHead = newVul.suffixHead;
            // // 获取正确后缀实现1
            // getSuffix = new VulStructure(suffixHead);
            // 获取正确后缀实现2
            Vector<Node> suffixPath;
            suffixPath = getDirectPath(suffixHead.direct_next);
            if(suffixPath.size() == 0)
                return;
            getSuffix = new VulStructure(suffixPath, newVul.regex);

            getSuffix.checkPathSharing();
            if(getSuffix.pumpSets.size()==0)
                return;
            correctSuffix = new Vector<>();
            correctSuffix.addAll(getSuffix.pumpSets.get(getSuffix.pumpSets.size() - 1));
            for(Vector<Set<Integer>> oneCorrectSuffix : getSuffix.pumpSets){
                for(int i = 0; i < oneCorrectSuffix.size(); i++){
                    correctSuffix.get(i).addAll(oneCorrectSuffix.get(i));
                }
            }

            // 优化③
            for(int i = 0; i < infix.size(); i++){
                infix.get(i).retainAll(correctSuffix.get(i));
            }

            // remove prefix from infix
            for(int i = 0; i < infix.size(); i++){
                infix.get(i).remove(prefix.charAt(i));
            }
        }

        finalVul(VulStructure newVul, VulStructure newVul2){
            type = VulType.POA;
            vul = newVul;
            vul2 = newVul2;
            infix = new Vector<>();

            prefix = newVul.prefix;
            suffix = newVul2.suffix;

            suffixHead = newVul2.suffixHead;
            // // 获取正确后缀实现1
            // getSuffix = new VulStructure(suffixHead);
            // 获取正确后缀实现2
            Vector<Node> suffixPath;
            suffixPath = getDirectPath(suffixHead.direct_next);
            if(suffixPath.size() == 0)
                return;
            getSuffix = new VulStructure(suffixPath, newVul.regex);

            getSuffix.checkPathSharing();
            if(getSuffix.pumpSets.size()==0)
                return;
            correctSuffix = new Vector<>();
            correctSuffix.addAll(getSuffix.pumpSets.get(getSuffix.pumpSets.size() - 1));
            for(Vector<Set<Integer>> oneCorrectSuffix : getSuffix.pumpSets){
                for(int i = 0; i < oneCorrectSuffix.size(); i++){
                    correctSuffix.get(i).addAll(oneCorrectSuffix.get(i));
                }
            }

            // 优化③
            for(int i = 0; i < infix.size(); i++){
                infix.get(i).retainAll(correctSuffix.get(i));
            }
        }

        /**
         * 获取用于重复的中缀字符串
         */
        public void getInfix() {
            // EOD、EOA、NQ
            if(type == VulType.ONE_COUNTING){
                // Collections.sort(vul.pumpSets,(l1, l2) -> Integer.compare(l1.size(), l2.size()));
                ListIterator aItr = vul.pumpSets.listIterator();
                while(aItr.hasNext()){
                    Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                    // ListIterator bItr = vul.pumpSets.listIterator();
                    ListIterator bItr = vul.pumpSets.listIterator(aItr.previousIndex());
                    while(bItr.hasNext()){
                        Vector<Set<Integer>> b = (Vector<Set<Integer>>) bItr.next();
                        if(b.size() != a.size())break;
                        if(redosPattern.setsArrayEqual(a,b)){
                            infix.addAll(a);
                        }
                    }
                }
                // POA
            }
            else if(type == VulType.POA){

                // 如果中间间隔内容：先获取中间内容，再将其与首个Counting拼接，判断是否有能与第二个Counting完全重合的路径
                if(vul2.path_end == null || onDirectNext(vul2.path_end, vul.path_start)){
                    Vector<Set<Integer>> mid = getDirectPathSet(vul2.path_end, vul.path_start);
                    ListIterator aItr = vul2.pumpSets.listIterator();
                    while(aItr.hasNext()){
                        Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                        a.addAll(mid);
                        ListIterator bItr = vul.pumpSets.listIterator();
                        while (bItr.hasNext()) {
                            Vector<Set<Integer>> b = (Vector<Set<Integer>>) bItr.next();
                            if (b.size() != a.size()) break;
                            if (redosPattern.setsArrayEqual(a, b)) {
                                infix.addAll(a);
                            }
                        }
                    }
                }
                else if(vul.path_end == null || onDirectNext(vul.path_end, vul2.path_start)){
                    Vector<Set<Integer>> mid = getDirectPathSet(vul.path_end, vul2.path_start);
                    ListIterator aItr = vul.pumpSets.listIterator();
                    while(aItr.hasNext()){
                        Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                        a.addAll(mid);
                        ListIterator bItr = vul2.pumpSets.listIterator();
                        while (bItr.hasNext()) {
                            Vector<Set<Integer>> b = (Vector<Set<Integer>>) bItr.next();
                            if (b.size() != a.size()) break;
                            if (redosPattern.setsArrayEqual(a, b)) {
                                infix.addAll(a);
                            }
                        }
                    }
                }
                // 如果相邻，判断有没有路径完全重合
                else if(vul2.path_end.direct_next == vul.path_start || vul.path_end.direct_next == vul.path_start) {
                    // Collections.sort(vul.pumpSets, (l1, l2) -> Integer.compare(l1.size(), l2.size()));
                    // Collections.sort(vul2.pumpSets, (l1, l2) -> Integer.compare(l1.size(), l2.size()));
                    ListIterator aItr = vul.pumpSets.listIterator();
                    while (aItr.hasNext()) {
                        Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                        ListIterator bItr = vul2.pumpSets.listIterator();
                        while (bItr.hasNext()) {
                            Vector<Set<Integer>> b = (Vector<Set<Integer>>) bItr.next();
                            if (b.size() != a.size()) break;
                            if (redosPattern.setsArrayEqual(a, b)) {
                                infix.addAll(a);
                            }
                        }
                    }
                }

            }
            // SLQ：判断前缀是否是中缀的前缀
            else if(type == VulType.SLQ){
                Vector<Set<Integer>> prefixSets = getDirectPathSet(pattern.root, vul.path_start);
                ListIterator aItr = vul.pumpSets.listIterator();
                while(aItr.hasNext()) {
                    Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                    if(redosPattern.startsWith(a, prefixSets)){
                        infix.addAll(prefixSets);
                        infix.addAll(a);
                        break;
                    };
                }
            }
        }

        public void getpump(){
            pump = new StringBuffer();
            for(Set<Integer> tmp : infix){
                pump.append(tmp.iterator().next());
            }


            suffix.append(prefix);
            // suffix.append(pump);
            // 优化②，把后缀改成每个counting的反例重复n+1次
            if(correctSuffix == null)
                return;
            suffixSets = new Vector<>();
            for(Set<Integer> aSet : correctSuffix){
                Set<Integer> tmpSet = new HashSet<>();
                tmpSet.addAll(Pattern4Search.fullCharSet);
                tmpSet.retainAll(aSet);
                suffixSets.add(tmpSet);
            }
            suffixSets.addAll(suffixSets);
            for(Set<Integer> aSet : suffixSets){
                if(aSet.size() == 0 || aSet.iterator().next() == null){
                    suffix.append("");
                }
                else
                    suffix.append(aSet.iterator().next());
            }
        }
    }

    private class VulStructure {
        StringBuffer prefix;
        StringBuffer pump;
        Vector<Vector<Set<Integer>>> pumpSets;
        Vector<Vector<Set<Integer>>> pumpSets2;
        Vector<Set<Integer>> infix;
        StringBuffer suffix;
        Driver suffixDriver = null;
        Vector<Vector<Node>> pathSharing;
        Vector<Node> fullPath;
        Vector<Node> path;
        Node path_start;
        Node path_start2;
        Node path_end;
        Node path_end2;
        Node suffixHead;
        Node curAtom;
        VulType type;
        Existance result = Existance.NOT_SURE;
        String regex;
        int beginFlag;
        int endFlag;
        private Object MyComparator;

        private class MatchGenerator {
            Node curNode = null;
            Map<Node, MatchGenerator> nextSliceSetUnsatisfied = null;
            Map<Node, MatchGenerator> nextSliceSetSatisfied = null;
            Map<Node, MatchGenerator> nextSliceSetMendatory = null;
            int min = 1;
            int max = 1;
            boolean isEnd = false;

            public MatchGenerator(Node node) {
                curNode = node;
                if (node == null) {
                    min = 0;
                    max = 0;
                }
                else {
                    min = pattern.getMinCount(node);
                    max = pattern.getMaxCount(node);
                    if (max > 10)
                        max = 10;
                }
            }

            public void addMendatoryCase(Node node, MatchGenerator generator) {
                if (nextSliceSetMendatory == null)
                    nextSliceSetMendatory = new HashMap<Node, MatchGenerator>();
                nextSliceSetMendatory.put(node, generator);
                if (!pattern.isSlice(curNode)) {
                    if (nextSliceSetSatisfied == null)
                        nextSliceSetSatisfied = new HashMap<Node, MatchGenerator>();
                    nextSliceSetSatisfied.put(node, generator);
                }
            }

            public void addUnsatisfiedCase(Node node, MatchGenerator generator) {
                if (nextSliceSetUnsatisfied == null)
                    nextSliceSetUnsatisfied = new HashMap<Node, MatchGenerator>();
                nextSliceSetUnsatisfied.put(node, generator);
                if (!pattern.isSlice(curNode)) {
                    if (nextSliceSetSatisfied == null)
                        nextSliceSetSatisfied = new HashMap<Node, MatchGenerator>();
                    nextSliceSetSatisfied.put(node, generator);
                }
            }

            public boolean isUnsatisfied(int cur) {
                return cur < min;
            }

            public boolean isSatisfied(int cur) {
                return (cur == min || cur > min) && cur < max;
            }
        }

        private class Driver {
            DirectedEngine engine = null;
            MatchGenerator curGenerator = null;
            StringBuffer matchingPath = null;
            Vector<Set<Integer>> matchingSets = new Vector<>();
            Map<MatchGenerator, Integer> curCntSet = null;
            int cnt = 0;
            Set<Triplet<Driver, Node, MatchGenerator>> nextSlices = null;
            Set<Integer> nextCharSetFull = null;
            Map<Triplet<Driver, Node, MatchGenerator>, Set<Integer>> nextCharSetMap = null;
            // 有问题的Flag
            boolean reachFinal = false;

            public Driver(DirectedEngine engineSource) {
                engine = engineSource;
                curGenerator = engine.headGenerator;
                matchingPath = new StringBuffer();
                curCntSet = new HashMap<MatchGenerator, Integer>();
            }

            public Driver(Driver oldDriver) {
                engine = oldDriver.engine;
                curGenerator = oldDriver.curGenerator;
                matchingPath = new StringBuffer();
                matchingPath.append(oldDriver.matchingPath);
                matchingSets.addAll(oldDriver.matchingSets);
                curCntSet = new HashMap<MatchGenerator, Integer>();
                curCntSet.putAll(oldDriver.curCntSet);
                cnt = oldDriver.cnt;
                reachFinal = oldDriver.reachFinal;
            }

            public void setAs(Driver newDriver) {
                engine = newDriver.engine;
                curGenerator = newDriver.curGenerator;
                matchingPath = new StringBuffer();
                matchingPath.append(newDriver.matchingPath);
                curCntSet = new HashMap<MatchGenerator, Integer>();
                curCntSet.putAll(newDriver.curCntSet);
                cnt = newDriver.cnt;
                reachFinal = newDriver.reachFinal;
            }

            private boolean driverSatisfied() {
                if (reachFinal)
                    return true;
                else
                    if ((curGenerator == engine.finalGenerator && getState() != CurState.UNSATISFIED))
                    return true;
                else if (getState() == CurState.SATISFIED && hasNext(CurState.SATISFIED)
                        && curGenerator.nextSliceSetSatisfied.containsKey(null)) {
                    Driver newDriver = new Driver(this);
                    newDriver.pushForward(null, curGenerator.nextSliceSetSatisfied.get(null));
                    if (newDriver.driverSatisfied())
                        return true;
                }
                else if (getState() == CurState.ONLEAVE && hasNext(CurState.ONLEAVE)
                        && curGenerator.nextSliceSetMendatory.containsKey(null)) {
                    Driver newDriver = new Driver(this);
                    newDriver.pushForward(null, curGenerator.nextSliceSetMendatory.get(null));
                    if (newDriver.driverSatisfied())
                        return true;
                }
                return false;
            }

            public boolean notEnd() {
                return getState() == CurState.UNSATISFIED || hasNext(CurState.ONLEAVE);
            }

            public CurState getState() {
                if (curGenerator.isUnsatisfied(cnt))
                    return CurState.UNSATISFIED;
                else if (curGenerator.isSatisfied(cnt))
                    return CurState.SATISFIED;
                else
                    return CurState.ONLEAVE;
            }

            public boolean hasNext(CurState state) {
                switch (state) {
                    case UNSATISFIED:
                        return curGenerator.nextSliceSetUnsatisfied != null;
                    case SATISFIED:
                        return curGenerator.nextSliceSetSatisfied != null;
                    case ONLEAVE:
                        return curGenerator.nextSliceSetMendatory != null;
                }
                return false;
            }

            public void pushAny(CurState state) {
                switch (state) {
                    case UNSATISFIED:
                        Set<Node> nodeSet = curGenerator.nextSliceSetUnsatisfied.keySet();
                        Node nextSliceNode = nodeSet.iterator().next();
                        pushForward(nextSliceNode, curGenerator.nextSliceSetUnsatisfied.get(nextSliceNode));
                        break;
                    case SATISFIED:
                        nodeSet = curGenerator.nextSliceSetSatisfied.keySet();
                        nextSliceNode = nodeSet.iterator().next();
                        pushForward(nextSliceNode, curGenerator.nextSliceSetSatisfied.get(nextSliceNode));
                        break;
                    case ONLEAVE:
                        nodeSet = curGenerator.nextSliceSetMendatory.keySet();
                        nextSliceNode = nodeSet.iterator().next();
                        pushForward(nextSliceNode, curGenerator.nextSliceSetMendatory.get(nextSliceNode));
                        break;
                }
            }

            public void cntIncrease() {
                cnt += 1;
                curCntSet.put(curGenerator, cnt);
            }

            // 改造完成
            public void pushForward(Node sliceNode, MatchGenerator nextGeneratorSource) {
                boolean isEnd = curGenerator.isEnd; // get isEnd flag
                MatchGenerator nextGenerator = nextGeneratorSource;
                int lastCnt = 0;
                if (curCntSet.containsKey(nextGenerator) && isEnd) { // update curCntSet using isEnd
                    lastCnt = curCntSet.get(nextGenerator);
                    curCntSet.put(nextGenerator, lastCnt + 1);
                }
                else
                    curCntSet.put(nextGenerator, lastCnt);
                if (pattern.isSlice(sliceNode)) { // upadate matching path
                    matchingPath.append(pattern.getSlice(sliceNode));
                    // 改造：将slice内容放入matchingSets
                    matchingSets.addAll(pattern.getSliceSets(sliceNode));
                }

                cnt = curCntSet.get(nextGenerator); // update cur cnt
                curGenerator = nextGenerator; // update curGenerator = nextGeneratorSource
                // clear curCntSet if next generator reach a repetiton
                if (curGenerator == engine.headGenerator) {
                    reachFinal = true;
                    curCntSet.clear();
                }
                if (engine.notFinish(curGenerator, cnt)
                        && curGenerator.curNode == engine.directedPath.get(engine.index - 1))
                    engine.buildNext(curGenerator, cnt);
            }

            public String pushForward(Node sliceNode, MatchGenerator nextGeneratorSource, int ch) {
                String str = pattern.checkChar(sliceNode, ch);
                if (str == null)
                    return null;
                boolean isEnd = curGenerator.isEnd; // get isEnd flag
                MatchGenerator nextGenerator = nextGeneratorSource;
                int lastCnt = 0;
                if (curCntSet.containsKey(nextGenerator) && isEnd) { // update curCntSet using isEnd
                    lastCnt = curCntSet.get(nextGenerator);
                    curCntSet.put(nextGenerator, lastCnt + 1);
                }
                else if (sliceNode != null || isEnd)
                    curCntSet.put(nextGenerator, lastCnt + 1);
                else
                    curCntSet.put(nextGenerator, lastCnt);
                if (pattern.isSlice(sliceNode)) { // upadate matching path
                    matchingPath.append(PatternUtils.convertString(ch) + str);
                }
                cnt = curCntSet.get(nextGenerator); // update cur cnt
                curGenerator = nextGenerator; // update curGenerator = nextGeneratorSource
                // clear curCntSet if next generator reach a repetiton
                if (curGenerator == engine.headGenerator) {
                    reachFinal = true;
                    curCntSet.clear();
                }
                if (engine.notFinish(curGenerator, cnt)
                        && curGenerator.curNode == engine.directedPath.get(engine.index - 1))
                    engine.buildNext(curGenerator, cnt);
                return str;
            }

            // 改造: 改造出一个依靠Sets的pushForward
            public List<Set<Integer>> pushForward(Node sliceNode, MatchGenerator nextGeneratorSource, Set<Integer> ch) {
                List<Set<Integer>> str = pattern.checkSet(sliceNode, ch);
                if (str == null)
                    return null;
                ch = str.get(0);
                str = str.subList(1,str.size());
                boolean isEnd = curGenerator.isEnd; // get isEnd flag
                MatchGenerator nextGenerator = nextGeneratorSource;
                int lastCnt = 0;
                if (curCntSet.containsKey(nextGenerator) && isEnd) { // update curCntSet using isEnd
                    lastCnt = curCntSet.get(nextGenerator);
                    curCntSet.put(nextGenerator, lastCnt + 1);
                }
                else if (sliceNode != null || isEnd)
                    curCntSet.put(nextGenerator, lastCnt + 1);
                else
                    curCntSet.put(nextGenerator, lastCnt);
                if (pattern.isSlice(sliceNode)) { // upadate matching path
                    // matchingPath.append(PatternUtils.convertString(ch) + str);
                    // 修改: 在此处获得mathcingSets，且不影响matchingPath
                    matchingSets.add(ch);
                    matchingSets.addAll(str);
                    String strResult = "";
                    matchingPath.append(PatternUtils.convertString((char)((int)ch.iterator().next())));
                    for(Set<Integer> tmp : str){
                        strResult = strResult + (char)((int)tmp.iterator().next());
                        matchingPath.append(PatternUtils.convertString((char)((int)tmp.iterator().next())));
                    }
                }
                cnt = curCntSet.get(nextGenerator); // update cur cnt
                curGenerator = nextGenerator; // update curGenerator = nextGeneratorSource
                // clear curCntSet if next generator reach a repetiton
                if (curGenerator == engine.headGenerator) {
                    reachFinal = true;
                    curCntSet.clear();
                }
                if (engine.notFinish(curGenerator, cnt)
                        && curGenerator.curNode == engine.directedPath.get(engine.index - 1))
                    engine.buildNext(curGenerator, cnt);
                return str;
            }

            private void update(Map<Node, MatchGenerator> map, MatchGenerator startGenerator) {
                if (curGenerator == startGenerator)
                    return;
                if (startGenerator == null)
                    startGenerator = curGenerator;
                if (map.containsKey(null) && map.size() == 1) {
                    if (curGenerator.isEnd && !(map == curGenerator.nextSliceSetUnsatisfied)) {
                        nextSlices = null;
                        return;
                    }
                    pushForward(null, map.get(null));
                    getNextSlices(startGenerator);
                    return;
                }
                else {
                    nextSlices = new HashSet<Triplet<Driver, Node, MatchGenerator>>();

                    for (Node node : map.keySet()) {
                        if (node == null && (!curGenerator.isEnd || curGenerator.nextSliceSetMendatory != map)) {
                            Driver newDriver = new Driver(this);
                            MatchGenerator nextGenerator = map.get(null);
                            newDriver.pushForward(null, nextGenerator);
                            newDriver.getNextSlices(startGenerator);
                            Set<Triplet<Driver, Node, MatchGenerator>> additionalSlice = newDriver.nextSlices;
                            if (additionalSlice != null)
                                nextSlices.addAll(additionalSlice);
                        }
                        else if (node != null) {
                            Triplet<Driver, Node, MatchGenerator> triplet = new Triplet<Driver, Node, MatchGenerator>(
                                    this, node, map.get(node));
                            nextSlices.add(triplet);
                        }
                    }
                }
            }

            public void getNextSlices() {
                if (getState() == CurState.UNSATISFIED && hasNext(CurState.UNSATISFIED)) {
                    update(curGenerator.nextSliceSetUnsatisfied, null);
                }
                else if (getState() == CurState.ONLEAVE && hasNext(CurState.ONLEAVE)) {
                    update(curGenerator.nextSliceSetMendatory, null);
                }
                else if (getState() == CurState.SATISFIED && hasNext(CurState.SATISFIED)) {
                    update(curGenerator.nextSliceSetSatisfied, null);
                }
                else
                    nextSlices = null;
            }

            public void getNextSlices(MatchGenerator startGenerator) {
                if (getState() == CurState.UNSATISFIED && hasNext(CurState.UNSATISFIED)) {
                    update(curGenerator.nextSliceSetUnsatisfied, startGenerator);
                }
                else if (getState() == CurState.ONLEAVE && hasNext(CurState.ONLEAVE)) {
                    update(curGenerator.nextSliceSetMendatory, startGenerator);
                }
                else if (getState() == CurState.SATISFIED && hasNext(CurState.SATISFIED)) {
                    update(curGenerator.nextSliceSetSatisfied, startGenerator);
                }
                else
                    nextSlices = null;
            }

            public void getNextCharSet() {
                nextCharSetFull = new HashSet<Integer>();
                nextCharSetMap = new HashMap<Triplet<Driver, Node, MatchGenerator>, Set<Integer>>();
                for (Triplet<Driver, Node, MatchGenerator> triplet : nextSlices) {
                    Set<Integer> charSet = pattern.getMatchSet(triplet.getValue1());
                    if (charSet != null) {
                        nextCharSetMap.put(triplet, charSet);
                        nextCharSetFull.addAll(charSet);
                    }
                }
            }

            public String getShortestFailedMatch() {
                String failedMatch = "";
                Vector<Driver> allDrivers = new Vector<Driver>();
                allDrivers.add(this);
                int size = 1;

                for (int i = 0; i < size; i++) {
                    Driver driver = allDrivers.get(i);
                    driver.getNextSlices();
                    Set<Triplet<Driver, Node, MatchGenerator>> nextSlices = driver.nextSlices;
                    if (nextSlices == null) {
                        continue;
                    }
                    Set<Node> nextSliceNode = null;
                    for (Triplet<Driver, Node, MatchGenerator> triplet : nextSlices) {
                        if (nextSliceNode == null)
                            nextSliceNode = new HashSet<Node>();
                        nextSliceNode.add(triplet.getValue1());
                    }
                    String failedCore = pattern.getUnMatch(nextSliceNode);
                    if (failedCore != null) {
                        failedMatch = driver.matchingPath.toString() + failedCore;
                        break;
                    }
                    else {
                        for (Triplet<Driver, Node, MatchGenerator> triplet : nextSlices) {
                            Driver curDriver = triplet.getValue0();
                            curDriver.pushForward(triplet.getValue1(), triplet.getValue2());
                            allDrivers.add(curDriver);
                            size += 1;
                        }
                    }
                }

                return failedMatch;
            }

            public void traverseToLast() {
                MatchGenerator coreGenerator = engine.headGenerator.nextSliceSetMendatory.values().iterator().next();
                Vector<Driver> genSet = new Vector<Driver>();
                curGenerator = coreGenerator;
                cnt = 0;
                curCntSet.clear();
                matchingPath.setLength(0);
                for (Node node : curGenerator.nextSliceSetUnsatisfied.keySet()) {
                    MatchGenerator nextGen = curGenerator.nextSliceSetUnsatisfied.get(node);
                    if (nextGen.isEnd && nextGen.nextSliceSetMendatory != null
                            && nextGen.nextSliceSetMendatory.containsValue(coreGenerator))
                        break;
                    Driver newDriver = new Driver(this);
                    newDriver.pushForward(node, nextGen);
                    genSet.add(newDriver);
                }
                int size = genSet.size();
                for (int i = 0; i < size; i++) {
                    Driver curDriver = genSet.get(i);
                    for (Node node : curDriver.curGenerator.nextSliceSetMendatory.keySet()) {
                        MatchGenerator nextGen = curDriver.curGenerator.nextSliceSetMendatory.get(node);
                        if (nextGen.isEnd && nextGen.nextSliceSetMendatory != null
                                && nextGen.nextSliceSetMendatory.containsValue(coreGenerator)) {
                            setAs(curDriver);
                            cnt = curGenerator.max;
                            break;
                        }
                        Driver newDriver = new Driver(curDriver);
                        newDriver.pushForward(node, curDriver.curGenerator.nextSliceSetMendatory.get(node));
                        genSet.add(newDriver);
                        size += 1;
                    }
                }
            }
        }

        private class DirectedEngine {
            Vector<Node> directedPath = null;
            Map<Node, MatchGenerator> allGenerators = null;
            MatchGenerator headGenerator = new MatchGenerator(null);
            MatchGenerator lastGenerator = headGenerator;
            MatchGenerator finalGenerator = null;
            int index = -1;
            boolean suffix = false;

            public DirectedEngine() {
                directedPath = new Vector<Node>();
                index = 0;
            }

            public DirectedEngine(Vector<Node> sourcePath) {
                directedPath = sourcePath;
                index = 0;
                buildToEnd();
            }

            public void buildToEnd() {
                while (index < directedPath.size()) {
                    Node node = directedPath.get(index);
                    Node next_node = null;
                    if (index < directedPath.size() - 1)
                        next_node = directedPath.get(index + 1);
                    if (next_node != null && (next_node == node.sub_next
                            || (node.new_atoms != null && Arrays.asList(node.new_atoms).contains(next_node)))) {
                        index += 1;
                        continue;
                    }
                    lastGenerator = buildGenerators(node, lastGenerator, false, next_node);
                    index += 1;
                }
                finalGenerator = lastGenerator;
            }

            public DirectedEngine(Vector<Node> sourcePath, boolean suffixSource) {
                suffix = suffixSource;
                directedPath = sourcePath;
                MatchGenerator tmpGenerator = headGenerator;
                index = 0;
                while (directedPath.get(index).sub_next == null && directedPath.get(index).new_atoms == null
                        && !pattern.isSlice(directedPath.get(index)) && index < directedPath.size() - 1)
                    index += 1;
                do {
                    lastGenerator = tmpGenerator;
                    Node node = directedPath.get(index);
                    Node next_node = null;
                    if (index < directedPath.size() - 1)
                        next_node = directedPath.get(index + 1);
                    if (next_node != null && (next_node == node.sub_next
                            || (node.new_atoms != null && Arrays.asList(node.new_atoms).contains(next_node)))) {
                        index += 1;
                        continue;
                    }
                    tmpGenerator = buildGenerators(node, lastGenerator, false, next_node);
                    if (index == directedPath.size() - 1) {
                        if (suffix)
                            tmpGenerator.nextSliceSetMendatory = null;
                        else if (tmpGenerator != headGenerator) {
                            tmpGenerator.addMendatoryCase(null, headGenerator);
                            finalGenerator = tmpGenerator;
                        }
                    }
                    if (index == 0 && suffix)
                        tmpGenerator.min = 0;
                    index += 1;
                } while (notFinish(lastGenerator, 0));
                lastGenerator = tmpGenerator;
            }

            private void addFromEnginePath(DirectedEngine nextEngine) {
                directedPath.addAll(nextEngine.directedPath);
                if (finalGenerator != null) {
                    finalGenerator.nextSliceSetMendatory = null;
                    if (finalGenerator.nextSliceSetSatisfied != null
                            && finalGenerator.nextSliceSetSatisfied.containsKey(null))
                        finalGenerator.nextSliceSetSatisfied.remove(null);
                    finalGenerator = null;
                }
            }

            private void addFromEngine(DirectedEngine nextEngine) {
                Map<Node, MatchGenerator> map = nextEngine.headGenerator.nextSliceSetMendatory;
                if (map == null) {
                    finalGenerator.addMendatoryCase(null, headGenerator);
                    return;
                }
                MatchGenerator nextHead = map.values().iterator().next();
                lastGenerator = nextEngine.lastGenerator;
                finalGenerator.addMendatoryCase(null, nextHead);
                if (nextEngine.finalGenerator != null) {
                    nextEngine.finalGenerator.addMendatoryCase(null, headGenerator);
                    finalGenerator = nextEngine.finalGenerator;
                }
                else {
                    if (nextEngine.index < nextEngine.directedPath.size())
                        directedPath.addAll(nextEngine.directedPath);
                    index = index + nextEngine.index;
                    finalGenerator = null;
                }
            }

            private void buildNext(MatchGenerator lastGeneratorSource, int cnt) {
                MatchGenerator tmpGenerator = lastGeneratorSource;
                int count = 0;
                do {
                    lastGenerator = tmpGenerator;
                    Node node = directedPath.get(index);
                    Node next_node = null;
                    if (index < directedPath.size() - 1)
                        next_node = directedPath.get(index + 1);
                    if (next_node != null && (next_node == node.sub_next
                            || (node.new_atoms != null && Arrays.asList(node.new_atoms).contains(next_node)))) {
                        index += 1;
                        count = (lastGenerator == lastGeneratorSource) ? cnt : 0;
                        continue;
                    }
                    tmpGenerator = buildGenerators(node, lastGenerator, false, next_node);
                    if (index == directedPath.size() - 1) {
                        if (suffix)
                            tmpGenerator.nextSliceSetMendatory = null;
                        else if (tmpGenerator != headGenerator) {
                            tmpGenerator.addMendatoryCase(null, headGenerator);
                            finalGenerator = tmpGenerator;
                        }
                    }
                    index += 1;
                    count = (lastGenerator == lastGeneratorSource) ? cnt : 0;
                } while (notFinish(lastGenerator, count));
                lastGenerator = tmpGenerator;
            }

            private boolean notFinish(MatchGenerator generator, int cnt) {
                return !generator.isUnsatisfied(cnt) && generator.nextSliceSetMendatory == null
                        && index < directedPath.size();
            }

            public String getShortestMatching() {
                Driver driver = new Driver(this);
                while (driver.notEnd()) {
                    if (driver.getState() == CurState.UNSATISFIED) {
                        if (driver.hasNext(CurState.UNSATISFIED)) {
                            driver.pushAny(CurState.UNSATISFIED);
                        }
                        else {
                            driver.cntIncrease();
                        }
                    }
                    else {
                        driver.pushAny(CurState.ONLEAVE);
                    }
                }

                return driver.matchingPath.toString();
            }

            private MatchGenerator buildGenerators(Node node, MatchGenerator lastGeneratorTmp, boolean sub,
                                                   Node next_node) {
                Node lastNode = lastGeneratorTmp.curNode;
                MatchGenerator nextGenerator = lastGeneratorTmp;

                if (node.sub_next != null || (node.new_atoms != null && next_node != null) || pattern.isSlice(node)) { // cur
                    // is
                    // meaningful
                    if (allGenerators == null)
                        allGenerators = new HashMap<Node, MatchGenerator>();
                    MatchGenerator newGenerator = new MatchGenerator(node);
                    allGenerators.put(node, newGenerator);
                    if (node.direct_next != null && node.direct_next.direct_prev != node)
                        allGenerators.put(node.direct_next.direct_prev, newGenerator);
                    nextGenerator = newGenerator;
                    // got new generator

                    if (lastNode != null) { // last is meaningful
                        Node p = node;
                        while (p != lastNode && p != null) {
                            if (p == lastNode.direct_next || p == lastNode.sub_next
                                    || lastNode.new_atoms != null && Arrays.asList(lastNode.new_atoms).contains(p))
                                break;
                            p = p.direct_prev;
                        }
                        if (p == null || p == lastNode.direct_next) {
                            if (pattern.isSlice(node)) { // last generator is slice type
                                lastGeneratorTmp.addMendatoryCase(node, newGenerator);
                            }
                            else { // equal to its next
                                lastGeneratorTmp.addMendatoryCase(null, newGenerator);
                            }

                        }
                        else if (p == lastNode.sub_next
                                || lastNode.new_atoms != null && Arrays.asList(lastNode.new_atoms).contains(p)) {
                            if (pattern.isSlice(node)) { // last generator is slice type
                                lastGeneratorTmp.addUnsatisfiedCase(node, newGenerator);
                            }
                            else { // equal to its next
                                lastGeneratorTmp.addUnsatisfiedCase(null, newGenerator);
                            }

                        }
                        else { // TODO : backref condition

                        }
                    }
                    else { // the begin Generator
                        if (pattern.isSlice(node)) { // last generator is slice type
                            lastGeneratorTmp.addMendatoryCase(node, newGenerator);
                        }
                        else { // equal to its next
                            lastGeneratorTmp.addMendatoryCase(null, newGenerator);
                        }
                    }

                    if (sub) {
                        Node p = node.direct_next;
                        while (p != null) {
                            if (p.sub_next != null || p.new_atoms != null || pattern.isSlice(p))
                                break;
                            p = p.direct_next;
                        }

                        if (p == null) { // reach end of sub path
                            newGenerator.isEnd = true;
                            p = node;
                            while (p != null) {
                                if (p.direct_prev.direct_next != p)
                                    break;
                                p = p.direct_prev;
                            }
                            if (p != null) {
                                MatchGenerator subPathEnd = allGenerators.get(p.direct_prev);
                                newGenerator.addMendatoryCase(null, subPathEnd);
                            }
                        }
                    }
                }

                if (node.sub_next != null) {
                    if (sub)
                        buildGenerators(node.sub_next, nextGenerator, true, node.sub_next.direct_next);
                    else
                        buildGenerators(node.sub_next, nextGenerator, true, null);
                    if (node.sub_next == next_node) {
                        nextGenerator.nextSliceSetMendatory = nextGenerator.nextSliceSetSatisfied;
                        nextGenerator.min = 0;
                    }
                }
                else if (node.new_atoms != null && next_node != null) {
                    if (next_node.self != "BranchEnd") {
                        if (sub)
                            buildGenerators(next_node, nextGenerator, true, next_node.direct_next);
                        else
                            buildGenerators(next_node, nextGenerator, true, null);
                        nextGenerator.nextSliceSetMendatory = nextGenerator.nextSliceSetSatisfied;
                        nextGenerator.min = 0;
                    }
                    else {
                        for (Node atom : node.new_atoms) {
                            buildGenerators(atom, nextGenerator, true, atom.direct_next);
                        }
                    }
                }

                if (sub && node.direct_next != null)
                    buildGenerators(node.direct_next, nextGenerator, true, node.direct_next.direct_next);

                return nextGenerator;
            }
        }

        public VulStructure(Vector<Node> sourcePath, VulType vulType) {
            initialize();
            path = sourcePath;
            type = vulType;
            path_start = path.get(0);
            path_end = path.get(path.size() - 1);
            path.remove(0);
            path.remove(path.size() - 1);
            if (path.size() > 0)
                // 如果除了起止节点还有别的东西的话，把中间这些东西通过addPath，检查是否存在实际字符，存在的话加入pathSharing
                addPath(path, true);
            switch (type) {
                case LOOP_IN_LOOP:
                    addPath(getDirectPath(path_end.direct_next), true);
                    addPath(getDirectPath(path_end.sub_next), false);
                    fullPath.addAll(path);
                    fullPath.add(path_end);
                    fullPath.addAll(getDirectPath(path_end.direct_next));
                    suffixHead = path_start;
                    break;
                case BRANCH_IN_LOOP:
                    addPath(getDirectPath(path_end.direct_next), true);
                    fullPath.addAll(path);
                    fullPath.add(path_end);
                    suffixHead = path_start;
                    break;
                case LOOP_AFTER_LOOP:
                    // 把头和尾子串中的内容也过一遍addPath，看看有没有必要加入pathSharing
                    // addPath(getDirectPath(path_start.sub_next), false);
                    // addPath(getDirectPath(path_end.sub_next), false);
                    suffixHead = path_end;
                    break;
            }
        }

        public VulStructure(Node node, String r) {
            initialize();
            path_start = node;
            path_end = node.direct_next;
            if(path_end == null)
                suffixHead = node;
            else
                suffixHead = path_end;

            addPath(getDirectPath(path_start.sub_next), false);
            regex = r;
            beginFlag = node.beginFlag;
            endFlag = node.endFlag;
            // Vector<Node> tmpPath = new Vector<Node>();
            // tmpPath.add(node);
            // pathSharing.add(tmpPath);
        }

        public VulStructure(Node node) {
            initialize();
            path_start = node;
            path_end = node.direct_next;
            suffixHead = path_end;
            addPath(getDirectPath(path_start.sub_next), false);
            // Vector<Node> tmpPath = new Vector<Node>();
            // tmpPath.add(node);
            // pathSharing.add(tmpPath);
        }

        public VulStructure(Vector<Node> sourcePath, String r) {
            initialize();
            path_start = sourcePath.get(0);
            path_end = sourcePath.get(sourcePath.size() - 1);
            addPath(sourcePath, false);
            regex = r;
            beginFlag = path_start.beginFlag;
            endFlag = r.length() - 1;
            type = VulType.GET_PUMP;
        }

        private String getPrefix() {
            Vector<Node> prefixPath = new Vector<Node>();
            Node p = path_start.direct_prev;
            if (p.self == "|")
                p = p.direct_prev;
            while (p != null) {
                prefixPath.add(0, p);
                p = p.direct_prev;
            }
            return getShortestMatching(prefixPath);
        }

        private boolean allSatisfied(Set<Driver> option) {
            for (Driver driver : option) {
                if (!driver.driverSatisfied())
                    return false;
            }
            return true;
        }

        private Set<Driver> getNewOption(Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> optionMap,
                                         int ch) {
            String sliceRemain = null;
            Driver driverRemain = null;
            Set<Driver> newDriverSet = new HashSet<Driver>();
            Set<Driver> nonSliceDriver = new HashSet<Driver>();

            for (Driver driver : optionMap.keySet()) {
                Quartet<Driver, Node, MatchGenerator, Set<Integer>> quartet = optionMap.get(driver);
                Driver newDriver = new Driver(quartet.getValue0());
                String str = newDriver.pushForward(quartet.getValue1(), quartet.getValue2(), ch);
                // push to next if is on leave without slice
                while (newDriver.getState() == CurState.ONLEAVE
                        && newDriver.curGenerator.nextSliceSetMendatory.size() == 1
                        && newDriver.curGenerator.nextSliceSetMendatory.containsKey(null))
                    // 改造：在此pushForward中，在获取matchingPath同时获取mathingSets
                    newDriver.pushForward(null, newDriver.curGenerator.nextSliceSetMendatory.get(null));
                if (str == null)
                    return null;
                else if (str != "") {
                    if (sliceRemain == null) {
                        sliceRemain = str;
                        driverRemain = newDriver;
                    }
                    else if (sliceRemain.length() > str.length()
                            && sliceRemain.substring(0, str.length()).equals(str)) {
                        sliceRemain = sliceRemain.substring(str.length());
                        nonSliceDriver.add(newDriver);
                    }
                    else if (sliceRemain.length() < str.length()
                            && sliceRemain.equals(str.substring(0, sliceRemain.length()))) {
                        sliceRemain = str.substring(sliceRemain.length());
                        nonSliceDriver.add(driverRemain);
                    }
                    else if (!sliceRemain.equals(str))
                        return null;
                }
                else
                    nonSliceDriver.add(newDriver);
                newDriverSet.add(newDriver);
            }

            if (sliceRemain != null) {
                for (Driver driver : nonSliceDriver) {
                    // TODO: could have multiple possibilities, currently push to one.
                    if (!pushSliceToSatisfied(driver, sliceRemain))
                        return null;
                }
            }

            return newDriverSet;
        }

        private Set<Driver> getNewOption(Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> optionMap,
                                         Set<Integer> ch) {
            List<Set<Integer>> sliceRemain = null;
            Driver driverRemain = null;
            Set<Driver> newDriverSet = new HashSet<Driver>();
            Set<Driver> nonSliceDriver = new HashSet<Driver>();

            for (Driver driver : optionMap.keySet()) {
                Quartet<Driver, Node, MatchGenerator, Set<Integer>> quartet = optionMap.get(driver);
                Driver newDriver = new Driver(quartet.getValue0());
                // 修改: 把这个pushForward()改为返回Set集合
                List<Set<Integer>> str = newDriver.pushForward(quartet.getValue1(), quartet.getValue2(), ch);
                // push to next if is on leave without slice
                while (newDriver.getState() == CurState.ONLEAVE
                        && newDriver.curGenerator.nextSliceSetMendatory.size() == 1
                        && newDriver.curGenerator.nextSliceSetMendatory.containsKey(null))
                    // 改造：在此pushForward中，在获取matchingPath同时获取mathingSets
                    newDriver.pushForward(null, newDriver.curGenerator.nextSliceSetMendatory.get(null));
                if (str == null)
                    return null;
                // else if (str != "") {
                else if (str.size() != 0) {
                    if (sliceRemain == null) {
                        sliceRemain = str;
                        driverRemain = newDriver;
                    }
                    // 改造: Vector<Set<Integer>> 之间的“equals”应该是“每一位互相的交集不为空”
                    // else if (sliceRemain.length() > str.length()
                    //         && sliceRemain.substring(0, str.length()).equals(str)) {
                    //     sliceRemain = sliceRemain.substring(str.length());
                    //     nonSliceDriver.add(newDriver);
                    // }
                    else if (sliceRemain.size() > str.size()
                            // && sliceRemain.subList(0, str.size()).equals(str)) {
                            && redosPattern.setsArrayEqual(sliceRemain.subList(0, str.size()), str)) {
                        // sliceRemain = (Vector<Set<Integer>>) sliceRemain.subList(str.size(), sliceRemain.size());
                        sliceRemain = new Vector<Set<Integer>>(str.subList(str.size(), sliceRemain.size()));
                        nonSliceDriver.add(newDriver);
                    }
                    // else if (sliceRemain.length() < str.length()
                    //         && sliceRemain.equals(str.substring(0, sliceRemain.length()))) {
                    //     sliceRemain = str.substring(sliceRemain.length());
                    //     nonSliceDriver.add(driverRemain);
                    // }
                    else if (sliceRemain.size() < str.size()
                            // && sliceRemain.equals(str.subList(0, sliceRemain.size()))) {
                            && redosPattern.setsArrayEqual(sliceRemain, str.subList(0, sliceRemain.size()))) {
                        // sliceRemain = (Vector<Set<Integer>>) str.subList(sliceRemain.size(), str.size());
                        sliceRemain = new Vector<Set<Integer>>(str.subList(sliceRemain.size(), str.size()));
                        nonSliceDriver.add(driverRemain);
                    }
                    // else if (!sliceRemain.equals(str))
                    else if (!redosPattern.setsArrayEqual(sliceRemain, str))
                        return null;
                }
                else
                    nonSliceDriver.add(newDriver);
                newDriverSet.add(newDriver);
            }

            if (sliceRemain != null) {
                for (Driver driver : nonSliceDriver) {
                    // TODO: could have multiple possibilities, currently push to one.
                    if (!pushSliceToSatisfied(driver, sliceRemain))
                        return null;
                }
            }

            return newDriverSet;
        }

        private boolean pushSliceToSatisfied(Driver driver, String str) {
            while (driver.getState() == CurState.ONLEAVE && driver.curGenerator.nextSliceSetMendatory.size() == 1
                    && driver.curGenerator.nextSliceSetMendatory.containsKey(null))
                // 改造：在此pushForward中，在获取matchingPath同时获取mathingSets
                driver.pushForward(null, driver.curGenerator.nextSliceSetMendatory.get(null));
            driver.getNextSlices();
            Set<Triplet<Driver, Node, MatchGenerator>> option = driver.nextSlices;
            if (option == null)
                return false;
            int ch = str.charAt(0);
            for (Triplet<Driver, Node, MatchGenerator> triplet : option) {
                Driver newDriver = new Driver(driver);
                // 改造: 使用返回Set集合的pushForward()
                String remainStr = newDriver.pushForward(triplet.getValue1(), triplet.getValue2(), ch);
                while (newDriver.getState() == CurState.ONLEAVE
                        && newDriver.curGenerator.nextSliceSetMendatory.size() == 1
                        && newDriver.curGenerator.nextSliceSetMendatory.containsKey(null))
                    // 改造：在此pushForward中，在获取matchingPath同时获取mathingSets
                    newDriver.pushForward(null, newDriver.curGenerator.nextSliceSetMendatory.get(null));
                if (remainStr != null) {
                    if (remainStr == "") {
                        if (str.length() == 1) {
                            driver.setAs(newDriver);
                            return true;
                        }
                        else {
                            newDriver.getNextSlices();
                            if (pushSliceToSatisfied(newDriver, str.substring(1))) {
                                driver.setAs(newDriver);
                                return true;
                            }
                        }
                    }
                    else if (remainStr.equals(str.substring(1))) {
                        driver.setAs(newDriver);
                        return true;
                    }
                    else if (str.length() > 1 + remainStr.length()
                            && str.substring(1, 1 + remainStr.length()) == remainStr) {
                        newDriver.getNextSlices();
                        if (str.substring(1).startsWith(remainStr)
                                && pushSliceToSatisfied(newDriver, str.substring(1 + remainStr.length()))) {
                            driver.setAs(newDriver);
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private boolean pushSliceToSatisfied(Driver driver, List<Set<Integer>> str) {
            while (driver.getState() == CurState.ONLEAVE && driver.curGenerator.nextSliceSetMendatory.size() == 1
                    && driver.curGenerator.nextSliceSetMendatory.containsKey(null))
                // 改造：在此pushForward中，在获取matchingPath同时获取mathingSets
                driver.pushForward(null, driver.curGenerator.nextSliceSetMendatory.get(null));
            driver.getNextSlices();
            Set<Triplet<Driver, Node, MatchGenerator>> option = driver.nextSlices;
            if (option == null)
                return false;
            // int ch = str.charAt(0);
            Set<Integer> ch = str.get(0);
            for (Triplet<Driver, Node, MatchGenerator> triplet : option) {
                Driver newDriver = new Driver(driver);
                List<Set<Integer>> remainStr = newDriver.pushForward(triplet.getValue1(), triplet.getValue2(), ch);
                while (newDriver.getState() == CurState.ONLEAVE
                        && newDriver.curGenerator.nextSliceSetMendatory.size() == 1
                        && newDriver.curGenerator.nextSliceSetMendatory.containsKey(null))
                    // 改造：在此pushForward中，在获取matchingPath同时获取mathingSets
                    newDriver.pushForward(null, newDriver.curGenerator.nextSliceSetMendatory.get(null));
                if (remainStr != null) {
                    if (remainStr.size() == 0) {
                        if (str.size() == 1) {
                            driver.setAs(newDriver);
                            return true;
                        }
                        else {
                            newDriver.getNextSlices();
                            // if (pushSliceToSatisfied(newDriver, str.substring(1))) {
                            if (pushSliceToSatisfied(newDriver, str.subList(1, str.size()))) {
                                driver.setAs(newDriver);
                                return true;
                            }
                        }
                    }
                    // else if (remainStr.equals(str.substring(1))) {
                    else if (redosPattern.setsArrayEqual(remainStr,str.subList(1,str.size()))) {
                        driver.setAs(newDriver);
                        return true;
                    }
                    else if (str.size() > 1 + remainStr.size()
                            // && str.substring(1, 1 + remainStr.length()) == remainStr) {
                            // Q: 为什么他这里用==而不想之前和getNewOptions一样用equals？
                            // A: 只有在pushForward传回str的就是ch的时候，原来的remainStr和str.substring才会相等
                            // Todo: 暂时还用setsArrayEqual代替，等待发现问题再修复
                            // && str.substring(1, 1 + remainStr.length()) == remainStr) {
                            && redosPattern.setsArrayEqual(str.subList(1, 1 + remainStr.size()), remainStr)) {
                        newDriver.getNextSlices();
                        // if (str.substring(1).startsWith(remainStr)
                        if (redosPattern.startsWith(str.subList(1, str.size()), remainStr)
                                // && pushSliceToSatisfied(newDriver, str.substring(1 + remainStr.length()))) {
                                && pushSliceToSatisfied(newDriver, str.subList(1 + remainStr.size(), str.size()))) {
                            driver.setAs(newDriver);
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private DirectedEngine getLoopEngine(boolean exclude) {
            DirectedEngine loopEngine = new DirectedEngine();
            MatchGenerator loop = loopEngine.buildGenerators(path_end, loopEngine.headGenerator, false, null);
            loopEngine.directedPath.add(path_end);
            loopEngine.index = 1;
            if (exclude)
                loop.max = loop.min;
            else
                loop.min = loop.min + 1;
            loop.addMendatoryCase(null, loopEngine.headGenerator);
            loopEngine.finalGenerator = loop;
            return loopEngine;
        }

        // exclude表示返回的DirectEngine是否只包含其他分支节点
        // irstChoiceEngine -> exclude = fruef
        // secondChoiceEngine -> exclude = false
        private DirectedEngine getBranchEngine(boolean exclude) {
            DirectedEngine branchEngine = new DirectedEngine();
            Node newBranch = ((Branch) path_end).getNewBranch();
            if (exclude) {
                List<Node> tmp = new Vector<Node>();
                for (Node a : newBranch.new_atoms) {
                    if (a != curAtom)
                        tmp.add(a);
                }
                newBranch.new_atoms = tmp.toArray(new Node[tmp.size()]);
            }
            else
                newBranch.new_atoms = new Node[]{curAtom};
            MatchGenerator branch = branchEngine.buildGenerators(newBranch, branchEngine.headGenerator, false,
                    newBranch.direct_next);
            branchEngine.directedPath.add(newBranch);
            branchEngine.index = 1;
            branch.addMendatoryCase(null, branchEngine.headGenerator);
            branchEngine.finalGenerator = branch;
            return branchEngine;
        }

        private Set<DirectedEngine> getEngineSet() {
            Set<DirectedEngine> engineSet = new HashSet<DirectedEngine>();
            // 对pathSharing中每条Path新建一个DirectEngine，存在engineSet中
            for (Vector<Node> tmpPath : pathSharing) {
                Vector<Node> pathCopy = new Vector<Node>(tmpPath);
                engineSet.add(new DirectedEngine(pathCopy, false));
            }
            // 对Branch in loop攻击类型，（猜测）pathSharing中只会有前缀path和后缀path
            if (type == VulType.BRANCH_IN_LOOP && path_end.self == "|") {
                DirectedEngine prefixEngine = null;
                DirectedEngine firstChoiceEngine = null;
                DirectedEngine secondChoiceEngine = null;
                DirectedEngine suffixEngine = null;

                // 遍历engineSet中所有DirectEngine，如果某个节点的的
                for (Iterator<DirectedEngine> i = engineSet.iterator(); i.hasNext(); ) {
                    DirectedEngine engine = i.next();
                    // engine.directPath在上面被设置为pathSharing中的对应path
                    // 如果这条路径的“结束节点”的下一个节点是这条路径的首个节点，则这个DirectEngine是后缀引擎
                    if (path_end.direct_next == engine.directedPath.get(0)) {
                        suffixEngine = engine;
                        i.remove();
                    }
                    // 如果不是后缀引擎就是前缀引擎
                    else {
                        prefixEngine = engine;
                        i.remove();
                    }
                }

                // 将几个分支都创建DirectEngine并加入EngineSet
                firstChoiceEngine = getBranchEngine(true);
                secondChoiceEngine = getBranchEngine(false);
                engineSet.add(firstChoiceEngine);
                engineSet.add(secondChoiceEngine);

                // 给两个分支节点添加信息（directedPath、finalGenerator.nextSliceSetMendatory）
                if (suffixEngine != null) {
                    firstChoiceEngine.addFromEnginePath(suffixEngine);
                    secondChoiceEngine.addFromEnginePath(suffixEngine);
                }

                // 使prefixEngine生成finalGenerator并加入firstChoiceEngine的finalGenerator，prefixEngineCopy加入secondChoiceEngine的finalGenerator
                if (prefixEngine != null) {
                    Vector<Node> newList = new Vector<Node>(prefixEngine.directedPath);
                    DirectedEngine prefixEngineCopy = new DirectedEngine(newList);
                    prefixEngine.buildToEnd();
                    prefixEngine.addFromEngine(firstChoiceEngine);
                    prefixEngineCopy.addFromEngine(secondChoiceEngine);
                    engineSet.clear();
                    engineSet.add(prefixEngine);
                    engineSet.add(prefixEngineCopy);
                }
            }
            //如果是LOOP_IN_LOOP节点
            else if (type == VulType.LOOP_IN_LOOP || (type == VulType.BRANCH_IN_LOOP && path_end.self == "?")) {
                DirectedEngine prefixEngine = null;
                DirectedEngine suffixEngine = null;
                for (Iterator<DirectedEngine> i = engineSet.iterator(); i.hasNext(); ) {
                    DirectedEngine engine = i.next();
                    i.remove();
                    if (path_end.sub_next == engine.directedPath.get(0) || (path_end.new_atoms != null
                            && Arrays.asList(path_end.new_atoms).contains(engine.directedPath.get(0))))
                        continue;
                    else if (path_end.direct_next == engine.directedPath.get(0))
                        suffixEngine = engine;
                    else
                        prefixEngine = engine;
                }

                DirectedEngine excludeLoopEngine = getLoopEngine(true);
                DirectedEngine forceLoopEngine = getLoopEngine(false);
                engineSet.add(excludeLoopEngine);
                engineSet.add(forceLoopEngine);

                if (suffixEngine == null && path_end.direct_next != null) {
                    suffixEngine = new DirectedEngine();
                    suffixEngine.directedPath.addAll(getDirectPath(path_end.direct_next));
                }
                if (suffixEngine != null) {
                    excludeLoopEngine.addFromEnginePath(suffixEngine);
                    forceLoopEngine.addFromEnginePath(suffixEngine);
                }

                if (prefixEngine != null) {
                    Vector<Node> newList = new Vector<Node>(prefixEngine.directedPath);
                    DirectedEngine prefixEngineCopy = new DirectedEngine(newList);
                    prefixEngine.buildToEnd();
                    prefixEngine.addFromEngine(excludeLoopEngine);
                    prefixEngineCopy.addFromEngine(forceLoopEngine);
                    engineSet.clear();
                    engineSet.add(prefixEngine);
                    engineSet.add(prefixEngineCopy);
                }
            }

            return engineSet;
        }

        private Vector<Set<Integer>> getPumpSet(){
            System.out.println(pathSharing);
            Vector<Set<Integer>> resultSet = new Vector<>();
            for(Node node : pathSharing.get(0)){
                resultSet.add(pattern.getMatchSetDIY(node));
            }
            // 清除空集合
            resultSet.removeIf(t -> t.contains(-2));
            return resultSet;
        }

        private Map<String, Vector<Set<Integer>>> getPump() {
            // 除了LOOP_IN_LOOP和BRANCH_IN_LOOP，一般都是给pathSharing中的每个path配一个engineSet
            Set<DirectedEngine> engineSet = getEngineSet();

            // 给每个engine配一个driver，并加入driverSet
            Set<Driver> driverSet = new HashSet<Driver>();
            for (DirectedEngine engine : engineSet) {
                Driver mainDriver = new Driver(engine);
                mainDriver.getNextSlices();
                if (mainDriver.nextSlices == null)
                    return null;
                driverSet.add(mainDriver);
            }

            Vector<Set<Driver>> setOfOptions = new Vector<Set<Driver>>();
            setOfOptions.add(driverSet);
            int size = 1;

            // String result = null;
            HashMap<String, Vector<Set<Integer>>> results = new HashMap<String, Vector<Set<Integer>>>();
            // // 记录Set序列
            // Map<Driver, Vector<Set<Integer>>> pumpSet = new HashMap<>();
            // Vector<Set<Integer>> pumpSetList = new Vector<Set<Integer>>();

            for (int i = 0; i < size; i++) {
                Set<Driver> option = setOfOptions.get(i);
                if (option.size() == 0)
                    continue;
                if (option.iterator().next().matchingPath.length() > 9)
                    continue;



                // 判断是否结束
                if (allSatisfied(option)) {
                    StringBuffer pathString = option.iterator().next().matchingPath;
                    Vector<Set<Integer>> pathVector = option.iterator().next().matchingSets;
                    if (pathString.length() > 0
                        // && (option.iterator().next().curGenerator != option.iterator().next().engine.lastGenerator
                        //     || option.iterator().next().curGenerator == option.iterator().next().engine.headGenerator)
                    ) {
                        // return pathString.toString();
                        results.put(pathString.toString(), pathVector);
                        // return results;
                    }
                }

                // add all next possibilities for each driver
                Set<Integer> nextChar = null;
                // their intersection
                for (Driver driver : option) {
                    driver.getNextSlices();
                    if (driver.nextSlices == null) {
                        nextChar = null;
                        break;
                    }
                    // nextCharSetFull里以Set形式存着所有下一个节点Integer
                    driver.getNextCharSet();
                    if (driver.nextCharSetFull.size() == 0) {
                        nextChar = null;
                        break;
                    }
                    if (nextChar == null) {
                        nextChar = new HashSet<Integer>();
                        nextChar.addAll(driver.nextCharSetFull);
                    }
                    else
                        nextChar.retainAll(driver.nextCharSetFull);
                }
                if (nextChar != null && nextChar.size() > 0) {
                    // get possible push options (remove non valid option)
                    Set<Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>> lastOptions = null;
                    for (Driver driver : option) {
                        for (Triplet<Driver, Node, MatchGenerator> triplet : driver.nextCharSetMap.keySet()) {
                            driver.nextCharSetMap.get(triplet).retainAll(nextChar);
                            if (driver.nextCharSetMap.get(triplet).size() == 0)
                                driver.nextSlices.remove(triplet);
                        }
                        // 新建lastOption，对driver的nextSlices中每个
                        if (lastOptions == null) {
                            lastOptions = new HashSet<Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>>();
                            for (Triplet<Driver, Node, MatchGenerator> triplet : driver.nextSlices) {
                                if (driver.nextCharSetMap.get(triplet) == null)
                                    continue;
                                Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> newMap = new HashMap<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>();
                                newMap.put(driver, triplet.addAt3(driver.nextCharSetMap.get(triplet)));
                                lastOptions.add(newMap);

                                // // 新建pumpSet元素
                                // Vector<Set<Integer>> newSetList = new Vector<Set<Integer>>();
                                // newSetList.add(driver.nextCharSetMap.get(triplet));
                                // pumpSet.put(driver, newSetList);
                            }
                        }
                        // 已有lastOption，生成并加入新的optionMap
                        else {
                            Set<Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>> newOptions = new HashSet<Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>>();
                            for (Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> lastMap : lastOptions) {
                                for (Triplet<Driver, Node, MatchGenerator> triplet : driver.nextSlices) {
                                    if (driver.nextCharSetMap.get(triplet) == null)
                                        continue;
                                    Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> newMap = new HashMap<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>();
                                    newMap.putAll(lastMap);
                                    newMap.put(driver, triplet.addAt3(driver.nextCharSetMap.get(triplet)));
                                    newOptions.add(newMap);

                                    // // 向pumpSet中记录
                                    // if(pumpSet.containsKey(driver))
                                    //     pumpSet.get(driver).add(driver.nextCharSetMap.get(triplet));
                                    // else {
                                    //     // 新建pumpSet元素
                                    //     Vector<Set<Integer>> newSetList = new Vector<Set<Integer>>();
                                    //     newSetList.add(driver.nextCharSetMap.get(triplet));
                                    //     pumpSet.put(driver, newSetList);
                                    // }
                                }
                            }
                            lastOptions = newOptions;
                        }
                    }

                    // 推进新的Options
                    for (Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> optionMap : lastOptions) {
                        Set<Integer> charSet = null;
                        // 对下一个字符求交集
                        for (Driver driver : optionMap.keySet()) {
                            if (charSet == null) {
                                charSet = new HashSet<Integer>();
                                charSet.addAll(optionMap.get(driver).getValue3());
                            }
                            else
                                charSet.retainAll(optionMap.get(driver).getValue3());
                            if (charSet.size() == 0)
                                break;
                        }

                        // 如果交集为空，则不再推进
                        if (charSet.size() == 0)
                            continue;
                        // 如果交集不为空加入，创建新一轮的Option迭代
                        else {
                            // 在这里更新了matchingPath
                            // Set<Driver> newOption = getNewOption(optionMap, charSet.iterator().next());
                            Set<Driver> newOption = getNewOption(optionMap, charSet);
                            if (newOption != null) {
                                setOfOptions.add(newOption);
                                size += 1;
                            }

                            // // // 向pumpSet中记录
                            // // pumpSetList.add(charSet);
                            // for(Driver driver : optionMap.keySet()){
                            //     if(pumpSet.containsKey(driver))
                            //         pumpSet.get(driver).add(charSet);
                            //     else {
                            //         // 新建pumpSet元素
                            //         Vector<Set<Integer>> newSetList = new Vector<Set<Integer>>();
                            //         newSetList.add(charSet);
                            //         pumpSet.put(driver, newSetList);
                            //     }
                            // }
                        }
                    }
                }
            }

            return results;
        }

        private String getSuffix() {
            Vector<Node> suffixPath = new Vector<Node>();
            Node p = suffixHead;
            while (p != null) {
                suffixPath.add(p);
                p = p.direct_next;
            }

            String suffix = "";
            try {
                DirectedEngine newEngine = new DirectedEngine(suffixPath, true);
                suffixDriver = new Driver(newEngine);
                suffix = suffixDriver.getShortestFailedMatch();
            } catch (Exception e) {
                System.out.print(regex + "\n");
                e.printStackTrace();
            }
            return suffix;
        }

        public class MyComparator implements Comparator{

            public int compare(Object o1, Object o2) {
                Vector p1 = (Vector) o1;
                Vector p2 = (Vector) o2;
                if (p1.size() < p2.size()) return 1;
                else return 0;
            }
        }

        /**
         * 获取用于重复的中缀字符串
         */
        public void getInfix() {
            // EOD、EOA、NQ
            if(type == VulType.ONE_COUNTING){
                Collections.sort(pumpSets,(l1, l2) -> Integer.compare(l1.size(), l2.size()));
                ListIterator aItr = pumpSets.listIterator();
                while(aItr.hasNext()){
                    Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                   // ListIterator bItr = pumpSets.listIterator();
                    ListIterator bItr = pumpSets.listIterator(aItr.previousIndex());
                    while(bItr.hasNext()){
                       Vector<Set<Integer>> b = (Vector<Set<Integer>>) bItr.next();
                       if(b.size() != a.size())break;
                       if(redosPattern.setsArrayEqual(a,b)){
                           infix.addAll(a);
                       }
                   }
                }
            // POA
            }else if(type == VulType.POA){
                // 如果相邻，判断有没有路径完全重合
                if(path_end2.direct_next == path_start || path_end.direct_next == path_start) {
                    Collections.sort(pumpSets, (l1, l2) -> Integer.compare(l1.size(), l2.size()));
                    Collections.sort(pumpSets2, (l1, l2) -> Integer.compare(l1.size(), l2.size()));
                    ListIterator aItr = pumpSets.listIterator();
                    while (aItr.hasNext()) {
                        Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                        ListIterator bItr = pumpSets2.listIterator();
                        while (bItr.hasNext()) {
                            Vector<Set<Integer>> b = (Vector<Set<Integer>>) bItr.next();
                            if (b.size() != a.size()) break;
                            if (redosPattern.setsArrayEqual(a, b)) {
                                infix.addAll(a);
                            }
                        }
                    }
                }
                // 如果中间间隔内容：先获取中间内容，再将其与首个Counting拼接，判断是否有能与第二个Counting完全重合的路径
                else if(onDirectNext(path_end2, path_start)){
                    Vector<Set<Integer>> mid = getDirectPathSet(path_end2, path_start);
                    ListIterator aItr = pumpSets2.listIterator();
                    while(aItr.hasNext()){
                        Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                        a.addAll(mid);
                        ListIterator bItr = pumpSets.listIterator();
                        while (bItr.hasNext()) {
                            Vector<Set<Integer>> b = (Vector<Set<Integer>>) bItr.next();
                            if (b.size() != a.size()) break;
                            if (redosPattern.setsArrayEqual(a, b)) {
                                infix.addAll(a);
                            }
                        }
                    }
                }else if(onDirectNext(path_end, path_start2)){
                    Vector<Set<Integer>> mid = getDirectPathSet(path_end, path_start2);
                    ListIterator aItr = pumpSets.listIterator();
                    while(aItr.hasNext()){
                        Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                        a.addAll(mid);
                        ListIterator bItr = pumpSets2.listIterator();
                        while (bItr.hasNext()) {
                            Vector<Set<Integer>> b = (Vector<Set<Integer>>) bItr.next();
                            if (b.size() != a.size()) break;
                            if (redosPattern.setsArrayEqual(a, b)) {
                                infix.addAll(a);
                            }
                        }
                    }
                }
            // SLQ：判断前缀是否是中缀的前缀
            }else if(type == VulType.SLQ){
                Vector<Set<Integer>> prefixSets = getDirectPathSet(pattern.root, path_start);
                ListIterator aItr = pumpSets.listIterator();
                while(aItr.hasNext()) {
                    Vector<Set<Integer>> a = (Vector<Set<Integer>>) aItr.next();
                    if(redosPattern.startsWith(a, prefixSets)){
                        infix.addAll(prefixSets);
                        infix.addAll(a);
                        break;
                    };
                }
            }
        }

        public void checkPathSharing() {
            if (pathSharing.size() == 0 && (type != VulType.BRANCH_IN_LOOP || path_end.self == "?"))
                result = Existance.NOT_EXIST;
            else {
                String pumpStr = null;
                Map<String, Vector<Set<Integer>>> pumpResult = null;
                // if (pathSharing.size() == 1 && (type != VulType.BRANCH_IN_LOOP || path_end.self == "?"))
                //     pumpStr = getShortestMatching(pathSharing.get(0));
                // else {
                    // 原版
                    // pumpStr = getPump();

                    // 改为Set之后
                    // Todo: 无法获取Branch中的其他分支
                pumpResult = getPump();

                // 进行筛选
                if(!(type == VulType.GET_PUMP))
                    for(Iterator<String> iterator = pumpResult.keySet().iterator();iterator.hasNext();) {
                        String key = iterator.next();
                        // 创建从原始正则中截取的子正则
                        // Pattern r = Pattern.compile(regex.substring(beginFlag, endFlag));
                        // Matcher m = r.matcher(key);
                        // m.find();
                        // 如果不符合条件，则移除
                        // if(!m.find()){
                        if(!Pattern.matches(regex.substring(beginFlag, endFlag), key)){
                            iterator.remove();
                        }
                    }
                if(pumpResult != null && pumpResult.size()>0)
                    pumpStr = pumpResult.keySet().iterator().next();

                if (pumpStr != null && pumpStr.length() > 0) {
                    pump.append(pumpStr);
                    if(!(type == VulType.GET_PUMP)) {
                        prefix.append(getPrefix());
                        suffix.append(getSuffix());
                    }
                    result = Existance.EXIST;

                    for (Map.Entry<String, Vector<Set<Integer>>> entry : pumpResult.entrySet()) {
                        pumpSets.add(entry.getValue());
                    }
                    // 排序pumpSets
                    Collections.sort(pumpSets,(l1, l2) -> Integer.compare(l1.size(), l2.size()));
                }
            }
        }

        private String getShortestMatching(Vector<Node> tmpPath) {
            String matching = "";
            try {
                DirectedEngine newEngine = new DirectedEngine(tmpPath);
                matching = newEngine.getShortestMatching();
            } catch (Exception e) {
                System.out.print(regex + "\n");
                e.printStackTrace();
            }
            return matching;
        }

        /**
         * hide 用作区分是否需要确认节点中有没有含有真实地字符，如果hide为false则默认tmpPath中有内容，直接加入pathSharing
         */
        public void addPath(Vector<Node> tmpPath, boolean hide) {
            if (hide) {
                for (int i = 0; i < tmpPath.size(); i++) {
                    Node node = tmpPath.get(i);
                    Node next_node = null;
                    // 如果不是是最后一个节点， 就把下一个节点放入next_node
                    if (i < tmpPath.size() - 1)
                        next_node = tmpPath.get(i + 1);
                    // 如果是最后一个节点，一般不做处理，任由next_node空着
                    // 但是如果tmpPath就是整个Vul的path，则把path_end作为next_node
                    else if (tmpPath == path)
                        next_node = path_end;

                    // 如果路径中存在next_node且next_node是当前节点的sub_next则继续——对应各种循环节点
                    if (next_node != null && node.sub_next == next_node)
                        continue;
                    // 如果路径中存在next_node且next_node是当前节点的分支中的某一条则继续——对应Branch
                    if (next_node != null && node.new_atoms != null
                            && Arrays.asList(node.new_atoms).contains(next_node))
                        continue;
                    // 如果节点中含有字符的话，将路径加入pathSharing并跳出循环
                    if (pattern.checkSlice(node, false)) {
                        pathSharing.add(tmpPath);
                        break;
                    }
                }
            }
            else
                // 默认传入的tmpPath中有内容，直接加入pathSharing
                pathSharing.add(tmpPath);
        }

        public void printResult(BufferedWriter outVul, int index) throws IOException {
            String complexType = "";
            switch (type) {
                case LOOP_IN_LOOP:
                case BRANCH_IN_LOOP:
                    complexType = "Exponential";
                    break;
                case LOOP_AFTER_LOOP:
                    complexType = "Polynomial";
                    break;
            }
            if (result != Existance.NOT_EXIST) {
                if (!possible_vulnerability) {
                    outVul.write(regex + "\n");
                    possible_vulnerability = true;
                }
                if (result == Existance.EXIST)
                    printVul(outVul, index, prefix.toString(), pump.toString(), suffix.toString(), complexType);
                else
                    printSharingPath(pathSharing, complexType, outVul);
            }
        }

        private void initialize() {
            prefix = new StringBuffer();
            pump = new StringBuffer();
            suffix = new StringBuffer();
            pathSharing = new Vector<Vector<Node>>();
            fullPath = new Vector<Node>();

            pumpSets = new Vector<>();
            pumpSets2 = new Vector<>();
        }
    }

    public enum Existance {
        EXIST, NOT_EXIST, NOT_SURE
    }

    public Analyzer(redosPattern regexPattern, int max_length) {
        pattern = regexPattern;
        maxLength = max_length;
        initialize();
        buildTree(pattern.root);
        removeInvalidLoop();
    }

    public Analyzer(redosPattern regexPattern, Pattern4Search p4s, int max_length) {
        pattern = regexPattern;
        pattern4Search = p4s;
        maxLength = max_length;
        initialize();
        buildTree(pattern.root);
        removeInvalidLoop();
    }

    public enum VulType {
        LOOP_IN_LOOP, BRANCH_IN_LOOP, LOOP_AFTER_LOOP,
        ONE_COUNTING, POA, SLQ,
        GET_PUMP
    }

    public enum CurState {
        SATISFIED, UNSATISFIED, ONLEAVE
    }

    public void doDynamicAnalysis(BufferedWriter outVul, int index, double threshold, int thresholdI) throws IOException {
        possibleVuls = new Vector<VulStructure>();

        // for (Vector<Node> path : loopInLoop) {
        //     VulStructure newVul = new VulStructure(path, VulType.LOOP_IN_LOOP);
        //     possibleVuls.add(newVul);
        // }

        // for (Vector<Node> path : branchInLoop) {
        //     Node pathEnd = path.get(path.size() - 1);
        //     if (pathEnd.self == "?") {
        //         VulStructure newVul = new VulStructure(path, VulType.BRANCH_IN_LOOP);
        //         newVul.fullPath.addAll(getDirectPath(pathEnd.new_atoms[0]));
        //         newVul.fullPath.addAll(getDirectPath(pathEnd.direct_next));
        //         newVul.addPath(getDirectPath(pathEnd.new_atoms[0]), false);
        //         possibleVuls.add(newVul);
        //     }
        //     else {
        //         for (Node atom : pathEnd.new_atoms) {
        //             Vector<Node> tmpPath = new Vector<Node>();
        //             tmpPath.addAll(path);
        //             VulStructure newVul = new VulStructure(tmpPath, VulType.BRANCH_IN_LOOP);
        //             newVul.curAtom = atom;
        //             possibleVuls.add(newVul);
        //             if (pathEnd.new_atoms.length == 2)
        //                 break;
        //         }
        //     }
        // }

        // for (Vector<Node> path : loopAfterLoop) {
        //     VulStructure newVul = new VulStructure(path, VulType.LOOP_AFTER_LOOP);
        //     possibleVuls.add(newVul);
        // }



        // Todo: 测试用临时代码
        for (Node node  : loopNodes) {
            // VulStructure newVul = new VulStructure(node);
            VulStructure newVul = new VulStructure(node, regex);
            possibleVuls.add(newVul);
        }

        for (VulStructure vulCase : possibleVuls) {
            vulCase.checkPathSharing();
            // vulCase.getInfix();
            // System.out.println(vulCase.infix);

            // if (vulCase.result == Existance.EXIST) {
            //     if (checkResult(vulCase.prefix.toString(), vulCase.pump.toString(), vulCase.suffix.toString(),
            //             maxLength, threshold)) {
            //         vulCase.printResult(outVul, index);
            //         break;
            //     }
            //     vulCase.suffixDriver.traverseToLast();
            //     String previousPath = vulCase.suffixDriver.matchingPath.toString();
            //     if (previousPath.length() > 1)
            //         previousPath = previousPath.substring(0, 1);
            //     else if (previousPath.length() == 0 && vulCase.suffixDriver.curGenerator.curNode.direct_next != null) {
            //         Set<Integer> nextMatchSet = pattern
            //                 .getFirstMatchSet(vulCase.suffixDriver.curGenerator.curNode.direct_next);
            //         if (nextMatchSet != null && nextMatchSet.size() > 0)
            //             previousPath = PatternUtils.convertString(nextMatchSet.iterator().next());
            //     }
            //     vulCase.suffixDriver.matchingPath.setLength(0);
            //     String lastFailedStr = vulCase.suffixDriver.getShortestFailedMatch();
            //     if (lastFailedStr == "")
            //         lastFailedStr = previousPath;
            //     if (checkResult(vulCase.prefix.toString(), vulCase.pump.toString(),
            //             vulCase.suffix.toString() + lastFailedStr, maxLength, threshold)) {
            //         vulCase.suffix.append(lastFailedStr);
            //         vulCase.printResult(outVul, index);
            //         break;
            //     }
            //     if (lastFailedStr != previousPath && previousPath != "" && checkResult(vulCase.prefix.toString(),
            //             vulCase.pump.toString(), vulCase.suffix.toString() + previousPath, maxLength, threshold)) {
            //         vulCase.suffix.setLength(vulCase.suffix.length() - lastFailedStr.length());
            //         vulCase.suffix.append(previousPath);
            //         vulCase.printResult(outVul, index);
            //         break;
            //     }
            // }
        }

        Vector<finalVul> possibleFinalVuls = new Vector<finalVul>();
        for(int i = 0; i < possibleVuls.size(); i++){
            possibleFinalVuls.add(new finalVul(possibleVuls.get(i), VulType.ONE_COUNTING));
            possibleFinalVuls.add(new finalVul(possibleVuls.get(i), VulType.SLQ));
            for(int j = i+1; j < possibleVuls.size(); j++){
                possibleFinalVuls.add(new finalVul(possibleVuls.get(i), possibleVuls.get(j)));
            }
        }

        for(finalVul vulCase : possibleFinalVuls){
            vulCase.getInfix();
            vulCase.getpump();
            if(vulCase.type == VulType.SLQ){
                if (vulCase.pump.length()!=0 && checkResult4Search(vulCase.prefix.toString(), vulCase.pump.toString(), vulCase.suffix.toString(),
                        maxLength, thresholdI)) {
                    // vulCase.printResult(outVul, index);
                    possible_vulnerability = true;
                    break;
                }
            }
            else if (vulCase.pump.length()!=0 && checkResult(vulCase.prefix.toString(), vulCase.pump.toString(), vulCase.suffix.toString(),
                    maxLength, threshold)) {
                // vulCase.printResult(outVul, index);
                possible_vulnerability = true;
                break;
            }
        }

        // System.out.println(possibleFinalVuls);

    }

    private boolean checkResult(String prefix, String pump, String suffix, int maxLength, double threshold) {
        double matchingStepCnt = 0;
        matchingStepCnt = pattern.getMatchingStepCnt(prefix, pump, suffix, maxLength, threshold);
        if (matchingStepCnt >= threshold)
            return true;
        return false;
    }

    private boolean checkResult4Search(String prefix, String pump, String suffix, int maxLength, int threshold) {
        double matchingStepCnt = 0;
        matchingStepCnt = pattern4Search.getMatchingStepCnt(prefix, pump, suffix, maxLength, threshold);
        if (matchingStepCnt >= threshold)
            return true;
        return false;
    }

    private boolean onDirectNext(Node pA, Node pB) {
        Node a = pA.direct_next;
        Node b = pB;
        if (a == null)
            return false;
        while (a != b && a.direct_next != null && a.sub_next == null && !(a instanceof Branch)) {
            if (pattern.isSlice(a))
                return false;
            a = a.direct_next;
        }
        return a == b;
    }

    public void doStaticAnalysis() {
        Vector<Node> loopNodeList = new Vector<Node>(loopNodes);
        for (int i = 0; i < loopNodeList.size() - 1; i++) {
            for (int j = i + 1; j < loopNodeList.size(); j++) {
                Node a = loopNodeList.get(i);
                Node b = loopNodeList.get(j);
                Node pA = pattern.getDirectParent(a);
                Node pB = pattern.getDirectParent(b);
//                if (onDirectNext(pA, pB) || pA.self == "|" && pA == pB) {
                if (onDirectNext(pA, pB)) {
                    Vector<Node> nPath = new Vector<Node>();
                    nPath.add(a);
                    nPath.add(b);
                    loopAfterLoop.add(nPath);
                }
                else if (onDirectNext(pB, pA)) {
                    Vector<Node> nPath = new Vector<Node>();
                    nPath.add(b);
                    nPath.add(a);
                    loopAfterLoop.add(nPath);
                }
            }
        }
        for (Node node : loopNodes) {
            Vector<Node> path = new Vector<Node>();
            path.add(node);
            if (node.direct_next != null)
                getPathFromLoop(node.direct_next, path, true);
            if (node.sub_next != null)
                getPathFromLoop(node.sub_next, path, false);
        }
    }

    private Vector<Node> getDirectPath(Node node) {
        Vector<Node> path = new Vector<Node>();
        while (node != null) {
            path.add(node);
            node = node.direct_next;
        }
        return path;
    }

    private Vector<Node> getDirectPathWithEnd(Node node) {
        Vector<Node> path = new Vector<Node>();
        while (node != null) {
            path.add(node);
            node = node.direct_next;
        }
        return path;
    }

    private Vector<Set<Integer>> getDirectPathSet(Node node, Node node2) {
        Vector<Set<Integer>> path = new Vector<>();
        while (node != null && node != node2) {
            if(node instanceof redosPattern.CharProperty)
            path.add(((redosPattern.CharProperty)node).charSet);
            node = node.direct_next;
        }
        return path;
    }

    private void printVul(BufferedWriter outVul, int index, String prefix, String pump, String suffix, String vulType)
            throws IOException {
        outVul.write("Find vulnerability (" + vulType + ") in structure!\n");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("regex", regex);
        jsonObject.put("prefix", prefix);
        jsonObject.put("pump", pump);
        jsonObject.put("suffix", suffix);
        if (index != -1)
            jsonObject.put("index", index);
        outVul.write(jsonObject + "\n");
    }

    private void printSharingPath(Vector<Vector<Node>> pathSharing, String complexity_type, BufferedWriter outVul)
            throws IOException {
        outVul.write(complexity_type + " complexity exist if these path below share same subexpression: \n");
        for (int i = 0; i < pathSharing.size(); i++)
            outVul.write(String.format("  p%d: ", i + 1) + getPathString(pathSharing.get(i)) + "\n");
    }

    private String getPathString(Vector<Node> path) {
        String str = new String();
        for (Node node : path) {
            if (node != null) {
                str += node.self;
                str += "->";
            }
        }
        return str;
    }

    private Vector<Vector<Node>> getCombination(Node[] atoms, int count) {
        Vector<Vector<Node>> combination = new Vector<Vector<Node>>();
        int atom_length = atoms.length;
        if (atom_length < count)
            return combination;

        boolean flag = false;

        int[] tempNum = new int[atom_length];
        for (int i = 0; i < atom_length; i++) {
            if (i < count)
                tempNum[i] = 1;
            else
                tempNum[i] = 0;
        }

        do {
            combination.add(createCombinationResult(atoms, tempNum, count));
            flag = false;
            for (int i = atom_length - count; i < atom_length; i++)
                if (tempNum[i] == 0)
                    flag = true;

            int pose = 0;
            int sum = 0;
            for (int i = 0; i < (atom_length - 1); i++) {
                if (tempNum[i] == 1 && tempNum[i + 1] == 0) {
                    tempNum[i] = 0;
                    tempNum[i + 1] = 1;
                    pose = i;
                    break;
                }
            }

            for (int i = 0; i < pose; i++)
                if (tempNum[i] == 1)
                    sum++;

            for (int i = 0; i < pose; i++) {
                if (i < sum)
                    tempNum[i] = 1;
                else
                    tempNum[i] = 0;
            }
        } while (flag);
        return combination;
    }

    private Vector<Node> createCombinationResult(Node[] a, int[] temp, int m) {
        Vector<Node> result = new Vector<Node>();
        for (int i = 0; i < a.length; i++)
            if (temp[i] == 1)
                result.add(a[i]);
        return result;
    }

    public boolean isVulnerable() {
        return possible_vulnerability;
    }

    private void getPathFromLoop(Node node, Vector<Node> prev_path, boolean direct) {
        if (node == null)
            return;
        Vector<Node> curr_path = new Vector<Node>();
        curr_path.addAll(prev_path);
        curr_path.add(node);
        if (pattern.isBacktrackLoop(node)) {
            if (direct)
                loopAfterLoop.add(curr_path);
            else if (!pattern.isCertainCntLoop(node))
                loopInLoop.add(curr_path);
            getPathFromLoop(node.direct_next, curr_path, direct);
            getPathFromLoop(node.sub_next, curr_path, direct);
        }
        else if (node instanceof Branch) {
            if (!direct)
                branchInLoop.add(curr_path);
            for (Node branch_node : node.new_atoms)
                getPathFromLoop(branch_node, curr_path, direct);
            getPathFromLoop(node.direct_next, curr_path, direct);
        }
        else if (node instanceof Ques && !direct) {
            branchInLoop.add(curr_path);
            node.new_atoms = new Node[]{node.atom};
            getPathFromLoop(node.direct_next, curr_path, direct);
        }
        else if (node.direct_next != null)
            getPathFromLoop(node.direct_next, curr_path, direct);
        else if (node.sub_next != null)
            getPathFromLoop(node.sub_next, curr_path, direct);
    }

    private void removeInvalidLoop() {
        for (Iterator<Node> i = loopNodes.iterator(); i.hasNext(); ) {
            Node element = i.next();
            if (pattern.lengthExceed(element, maxLength))
                i.remove();
        }
    }

    private void initialize() {
        possible_vulnerability = false;

        loopNodes = new HashSet<Node>();
        loopInLoop = new Vector<Vector<Node>>();
        branchInLoop = new Vector<Vector<Node>>();
        loopAfterLoop = new Vector<Vector<Node>>();

        regex = pattern.pattern();
    }

    private void buildTree(Node cur) {
        if (pattern.isBacktrackLoop(cur))
            loopNodes.add(cur);

        // System.out.println("current node: " + cur.self);
        Set<Node> outNodes = new HashSet<Node>();
        getNextNodes(cur, outNodes);
        if (outNodes.size() == 0)
            return;
        else if (outNodes.size() == 1) {
            for (Node node : outNodes) {
                // System.out.println(" sub node: " + node.self);
                if (node.self == "BranchEnd" && !(cur instanceof Branch))
                    return;
                else if (cur.self == ")" && node.body != null) {
                    return;
                }
                else if (cur instanceof Branch) {
                    List<Node> filter_atoms = new Vector<Node>();
                    for (Node a : cur.atoms) {
                        if (a != null)
                            filter_atoms.add(a);
                    }
                    cur.new_atoms = filter_atoms.toArray(new Node[filter_atoms.size()]);
                    for (Node a : cur.new_atoms) {
                        a.direct_prev = cur;
                        buildTree(a);
                    }
                }
                cur.direct_next = node;
                node.direct_prev = cur;
                buildTree(node);
            }
        }
        else if (outNodes.size() == 2) {
            for (Node node : outNodes) {
                // System.out.println(" sub node: " + node.self);
                if (cur.body == node || cur.atom == node || cur.cond == node)
                    cur.sub_next = node;
                else if (node.self != "BranchEnd")
                    cur.direct_next = node;
                node.direct_prev = cur;
                buildTree(node);
            }
        }
        else {
            System.out.println("out node exceeds 2");
            for (Node node : outNodes)
                System.out.println(" sub node: " + node.self);
        }
    }

    private void getNextNodes(Node cur, Set<Node> outNodes) {
        // Curly
        if (cur.atom != null)
            outNodes.add(cur.atom);
        // if (cur.atom_self != null)
        // Branch
        // if (cur.new_atoms != null)
        // Conn
        if (cur.conn != null)
            outNodes.add(cur.conn);
        // Loop
        if (cur.body != null)
            outNodes.add(cur.body);
        // Prolog
        if (cur.loop != null)
            outNodes.add(cur.loop);
        // GroupRef
        if (cur.head != null)
            outNodes.add(cur.head);
        // Conditional
        if (cur.cond != null)
            outNodes.add(cur.cond);
        // if (cur.yes != null)
        // if (cur.not != null)
        // Next
        if (cur.next != null && cur.next.self != "Exit")
            outNodes.add(cur.next);
        // if (cur.next_self != null) outNodes.add(cur.next_self);
    }
}