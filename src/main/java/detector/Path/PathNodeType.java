package detector.Path;

public enum PathNodeType {
    // 普通字符类
    CharSet,
    // lookaround
    LookAroundPos,
    LookAroundNeg,
    LookAroundBehind,
    LookAroundNotBehind,
    // 锚点"^"、"$"
    WordBoundaryLower,
    WordBoundaryUpper,
}
