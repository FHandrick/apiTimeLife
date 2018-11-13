# APITimeLife

A tool to identify API breaking and non-breaking changes between two versions of a Java library. apiTimeLife analyses libraries hosted on the distributed version control system _git_.

## Contributors
The project has been maintained by [Francisco Handrick](https://github.com/FHandrick) under supervision of Professor [Rodrigo Bonifácio](https://github.com/rbonifacio) ([CIC](https://cic.unb.br/) [UNB](https://www.unb.br/)).


## Catalog

The following _Breaking Changes_ (BC) are supported: 

| Element  | Breaking Changes (BC) |
| ------------- | ------------- |
| Type  | Rename Type, Move Type, Move and Rename Type, Remove Type, Lost Visibility, Add Final Modifier,  Remove Static Modifier, Change in Supertype, Remove Supertype |
| Method  | Move Method, Rename Method, Remove Method, Push Down Method, Inline Method, Change in Parameter List, Change in Exception List, Change in Return Type Method, Lost Visibility, Add Final Modifier, Remove Static Modifier  | 
| Field  |  Remove Field, Move Field, Push Down Field, Change in Default Value, Change in Type Field,  Lost Visibility, Add Final Modifier | 

The following _Non-breaking Changes_ (NBC) are supported: 

| Element  | Non-breaking Changes (NBC) |
| ------------- | ------------- |
| Type  | Add Type, Extract Supertype, Gain Visibility, Remove Final Modifier, Add Static Modifier, Add Supertype, Deprecated Type |
| Method  | Pull Up Method, Gain Visibility, Remove Final Modifier, Add Static Modifier, Deprecated Method, Add Method, Extract Method| 
| Field  | Pull Up Field, Add Field, Deprecated Field, Gain Visibility, Remove Final Modifier|


The refactorings catalog is reused from [apiDiff](https://github.com/aserg-ufmg/apidiff).

## Examples

* Detecting changes in version histories:

```java
APIDiff diff = new APIDiff("bcgit/bc-java", "https://github.com/bcgit/bc-java.git");
diff.setPath("/home/francisco/github");

Result result = diff.detectChangeAllHistory("master", Classifier.API);
for(Change changeMethod : result.getChangeMethod()){
    System.out.println("\n" + changeMethod.getCategory().getDisplayName() + " - " + changeMethod.getDescription());
}
```
* Detecting changes between two specific commit:

```java
APIDiff diff = new APIDiff("bcgit/bc-java", "https://github.com/bcgit/bc-java.git");
diff.setPath("/home/github");
Release re = new Release();
re.insert();
    	
for (int i = 0; i<re.comparison.size();i++) {	
	for(Change changeMethod : result.getChangeMethod()){
		System.out.println("\n" + changeMethod.getCategory().getDisplayName() + " - " + changeMethod.getDescription());
	}
}
```
* Filtering Packages according to their names:

```java 
Classifier.INTERNAL: Elements that are in packages with the term "internal".

Classifier.TEST: Elements that are in packages with the terms "test"|"tests", or is in source file "src/test", or ends with "test.java"|"tests.java".

Classifier.EXAMPLE: Elements that are in packages with the terms "example"|"examples"|"sample"|"samples"|"demo"|"demos"

Classifier.EXPERIMENTAL: Elements that are in packages with the term "experimental".

Classifier.NON_API: Internal, test, example or experimental elements.

Classifier.API: Elements that are not non-APIs.
``` 

## Usage

APITimeLife is available in the [Maven Central Repository](https://mvnrepository.com/artifact/com.github.aserg-ufmg/apiTimeLIfe/2.0.0):

```xml
<dependency>
    <groupId>com.github.fhandrick</groupId>
    <artifactId>apiTimeLIfe</artifactId>
    <version>2.0.0</version>
</dependency>
```
