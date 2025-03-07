# 项目报告

## 1.本地启动项目

拉取 https://github.com/javaweb-rasp/javaweb-vuln 至本地idea 并查看项目结构。
建立本地数据库javaweb-bbs，修改vuln-springboot3 application.properties配置数据库，启动springboot3Application能够正常运行。

## 2.新建vuln-agent模块

建立Agent类实现premain方法，在类加载前对类进行加强。
permain方法如下：注册了一个ClassFileTransformer，每当类进行加载时都会进行加强。可动态替换getApi方法的第二个参数扫描不同包下的api信息。

public static void premain(String agentArgs, Instrumentation inst) {

        System.out.println("-------------------------------------------------agent启动-----------------------------------------------------------");

        inst.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                //替换packageName，可检测不同包下的api  getApi是主方法
                getApi(className,loader,"org/javaweb/vuln/controller/");
                // 返回null表示不修改类文件
                return null;
            }
        });
    }
getApi是主方法，主要采取反射的机制，获取类的类名，类的url，类的方法，方法名，方法入参，方法注解，方法url，方法返回类型。
主要代码为：
Class<?> clazz = Class.forName(className.replace('/', '.'), false, loader);   反射获取类的信息

在resources下建立META-INF\MANIFEST.MF并进行配置

修改pom.xml文件，暴露META-INF\MANIFEST.MF文件。

## 3.将vuln-agent模块进行打成jar包

在springboot3Application中的run configuration添加 -javaagent:"D:\git repository\javaweb-vuln-agent\vuln-agent\target\vuln-agent-3.0.3.jar" 该路径是jar包的绝对路径。

## 4.重新运行springboot3Application

即可在D：\\apis下看到所有类的api的json格式，输出位一个.txt文件。

提取json结构如下：（可修改格式）
{
"className": "org.javaweb.vuln.controller.BlacklistController",
"methods": [{
    "requestType": "GET + POST",
    "methodName": "url",
    "returns": "Map<String, Object>",
    "params": {},
    "url": "http://localhost:8003//Blacklist/url.do"
}, {
    "requestType": "GET + POST",
    "methodName": "blacklist",
    "returns": "Map<String, Object>",
    "params": {},
    "url": "http://localhost:8003//Blacklist/blacklist.do"
}]
}