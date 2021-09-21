# burp-api-common
common methods used by myself. 

编写burp插件过程中积累的常用方法

### 使用方法一(推荐)

方法一基于[Github packages](https://github.com/bit4woo/burp-api-common/packages)

直接在pom.xml中添加如下依赖配置，位置在 `<dependencies>`的下级，version的值不包含“v”。

```xml
<dependency>
  <groupId>com.github.bit4woo</groupId>
  <artifactId>burp-api-common</artifactId>
  <version>0.1.3</version>
</dependency>
```



### 使用方法二(备选)

方法二基于[JitPack](https://jitpack.io/#jitpack/burp-api-common)

[![Release](https://jitpack.io/v/bit4woo/burp-api-common.svg)](https://jitpack.io/#bit4woo/burp-api-common)

To use it in your Maven build add:

在pom.xml文件中添加如下配置，位置在`<project>`的下级。

```xml
  <repositories>
	<repository>
	    <id>jitpack.io</id>
	    <url>https://jitpack.io</url>
	</repository>
  </repositories>
```

and the dependency:

 然后再添加如下依赖配置，位置在 `<dependencies>`的下级。**注意version的值包含一个“v”**。

```xml
<dependency>
    <groupId>com.github.bit4woo</groupId>
    <artifactId>burp-api-common</artifactId>
    <version>v0.1.3</version>
</dependency>
```



