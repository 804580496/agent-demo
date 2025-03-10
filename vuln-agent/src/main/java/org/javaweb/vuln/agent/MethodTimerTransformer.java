package org.javaweb.vuln.agent;

import javassist.*;
import javassist.bytecode.AnnotationsAttribute;
import javassist.bytecode.annotation.Annotation;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.*;

public class MethodTimerTransformer implements ClassFileTransformer {

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {

        // 仅处理目标包下的类
        if (className.startsWith("org/javaweb/vuln/controller/")) {
            try {
                // 使用Javassist解析类
                ClassPool pool = ClassPool.getDefault();
                pool.insertClassPath(new LoaderClassPath(loader));
                CtClass cc = pool.get(className.replace("/", "."));

                // 增强方法
                enhanceMethods(cc,className);

                return cc.toBytecode(); // 返回修改后的字节码
            } catch (Exception e) {
                e.printStackTrace();
                return null; // 如果发生异常，返回原始字节码
            }
        }
        return null; // 如果不是目标包下的类，不进行任何操作
    }


    private void enhanceMethods(CtClass ctClass,String className) throws CannotCompileException, NotFoundException {



        // 增强方法逻辑
        for (CtMethod method : ctClass.getDeclaredMethods()) {

            UUID uuid = UUID.randomUUID();
            String string = uuid.toString();

            // 获取方法返回类型
            CtClass returnType = method.getReturnType();

            // 检查方法是否为 void 类型
            if (!returnType.getName().equals("void")) {
                // 插入代码逻辑
                method.insertAfter("{ " +
                        "Object result = $_; " +
                        "java.util.Map tempMap = new java.util.HashMap();" +  // 初始化map移到if-else外部
                        "if (result != null) { " +
                        "   tempMap.put(\"status\", java.lang.Integer.valueOf(200));" +  // 显式转换
                        "   tempMap.put(\"result\", result);" +
                        "   tempMap.put(\"description\",\"OK\");" +
                        "   tempMap.put(\"uuid\",\"" + escapeForJavaStringLiteral(string) + "\");" + // 添加uuid
                        "   tempMap.put(\"type\",\"" + escapeForJavaStringLiteral(method.getReturnType().getName()) + "\");" +  // 将返回类型放入map
                        "   tempMap.put(\"time\", java.time.LocalDateTime.now().toString());" + // 添加当前时间
                        "} else {" +
                        "   tempMap.put(\"status\", java.lang.Integer.valueOf(404));" +
                        "   tempMap.put(\"result\", \"\"); " +
                        "   tempMap.put(\"type\",\"" + escapeForJavaStringLiteral(method.getReturnType().getName()) + "\");" +  // 对于void类型或其他情况同样处理
                        "   tempMap.put(\"time\", java.time.LocalDateTime.now().toString());" + // 添加当前时间
                        "} " +
                        "com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();" +
                        "String jsonResult = mapper.writeValueAsString(tempMap);" +
                        "System.out.println(\"方法返回结果(JSON): \" + jsonResult);" +
                        "}");
            } else {
                // 对于 void 方法的处理
                method.insertAfter("{ " +
                        "java.util.Map tempMap = new java.util.HashMap();" +
                        "tempMap.put(\"status\", java.lang.Integer.valueOf(200));" +
                        "tempMap.put(\"description\",\"OK\");" +
                        "System.out.println(\"方法执行成功，无返回值\");" +
                        "System.out.println(\"方法返回类型: void\");" +
                        "} ");
            }

        }
    }
    private static String escapeForJavaStringLiteral(String input) {
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

}
