# burp-api-common
common methods used by myself. 

编写burp插件过程中积累的常用方法

### 使用方法一(推荐)

基于[JitPack](https://jitpack.io/#jitpack/burp-api-common)

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

然后再添加如下依赖配置，位置在 `<dependencies>`的下级。

注意version字段，当使用“master-SNAPSHOT”作为版本时，会使用最新代码

```

<dependency>
    <groupId>com.github.bit4woo</groupId>
    <artifactId>burp-api-common</artifactId>
    <version>master-SNAPSHOT</version>
</dependency>
```

如果要使用具体版本配置如下，**注意version的值包含一个“v”**。

```xml
<dependency>
    <groupId>com.github.bit4woo</groupId>
    <artifactId>burp-api-common</artifactId>
    <version>v0.1.3</version>
</dependency>
```





### 使用方法二(备选)

基于[Github packages](https://github.com/bit4woo/burp-api-common/packages)

直接在pom.xml中添加如下依赖配置，位置在 `<dependencies>`的下级，version的值不包含“v”。

```xml
<dependency>
  <groupId>com.github.bit4woo</groupId>
  <artifactId>burp-api-common</artifactId>
  <version>0.1.3</version>
</dependency>
```

创建或修改/Users/user/.m2/setttings.xml 文件，如果使用过GitHub Packages，就无需再修改了。更多详情参考[这里](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry)

```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                      http://maven.apache.org/xsd/settings-1.0.0.xsd">

  <activeProfiles>
    <activeProfile>github</activeProfile>
  </activeProfiles>

  <profiles>
    <profile>
      <id>github</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo1.maven.org/maven2</url>
        </repository>
        <repository>
          <id>github</id>
          <url>https://maven.pkg.github.com/bit4woo/*</url>
          <snapshots>
            <enabled>true</enabled>
          </snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>

  <servers>
    <server>
      <id>github</id>
      <username>bit4woo</username>
      <password>Your-github-access-token</password>
    </server>
  </servers>

    <properties>  
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>  
        <maven.compiler.encoding>UTF-8</maven.compiler.encoding>  
    </properties> 
</settings>
```

