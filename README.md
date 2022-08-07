# RegexScalpel

RegexScalpel is an automatic regex repair framework that adopts a localize-and-fix strategy.

---

You can find more information in the paper "[RegexScalpel: Regular Expression Denial of Service (ReDoS) Defense by Localize-and-Fix](https://www.usenix.org/conference/usenixsecurity22/presentation/li-yeting)".

## Usage

This program runs under java8 environment.
You can find the main entrance to the program in the directory `/src/main/java/Main.java`.
The result of the regex fix will be generated by multiple rounds of fixes until one is generated without the ReDoS vulnerability.

**1. Interactively repair a single regex**

You can use the following code in `Main.java` to do an interactive repair of a single regex

```java
SingleTester.Test_Interactively("a*a*b");
```

The parameter is the regex to be fixed, which can be replaced by whatever you want. The repair results for each round will be selected by the user interactively with the program on the command line.

**2. Automatically repair a single regex**

You can use the following code in `Main.java` to do an automatic repair of a single regex

```java
SingleTester.Test_Automatically("a*a*b");
```

The parameter is the regex to be fixed, which can be replaced by whatever you want. The result of each round of repair will be chosen automatically and randomly by the program.

**3. Automatically repair regexs in dataset**

You can use the following code in `Main.java` to do an automatic repair of regexs in datasets

```java
DatasetTester.Test("data/input/CVE415-SOLA-DA.txt", "data/output/CVE415-SOLA-DA.txt");
```

The first parameter is the path of the input dataset. The example shown is the dataset from the paper. If you have provided your own dataset for testing, please change the path of the first parameter to your dataset file.
The second parameter is the path of the output dataset. If you wish to change the output path and the output file name, please change the second parameter.

# More Information

To see more experimental statistics from our paper, please check the following [links](https://sites.google.com/view/regexscalpel/abstract)