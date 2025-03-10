package org.javaweb.vuln.agent;

import com.alibaba.fastjson.JSONObject;
import javassist.*;
import javassist.bytecode.AnnotationsAttribute;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.*;
import java.security.ProtectionDomain;
import java.util.*;

/**
 * ClassName: ClassAndMethodTransformer
 * Package: org.javaweb.vuln.agent
 * Description:
 *
 * @Author DYH
 * @Create 2025/3/10 23:36
 * @Version 1.0
 */
public class ClassAndMethodTransformer implements ClassFileTransformer {
    public static String FILE_PATH = "D:\\apis\\";
    private Instrumentation instrumentation;

    public ClassAndMethodTransformer(Instrumentation instrumentation) {
        this.instrumentation = instrumentation;
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        // 仅处理目标包下的类
        if (className.startsWith("org/javaweb/vuln/controller/")) {
            try {
                // 使用Javassist解析类
                ClassPool pool = ClassPool.getDefault();
                pool.insertClassPath(new LoaderClassPath(loader));
                CtClass cc = pool.get(className.replace("/", "."));


                // 提取API信息
                //extractApiInfo(className,loader);

                // 增强方法
                enhanceMethods(cc);

                // 使用 Instrumentation.redefineClasses 来重新定义类
                Instrumentation instrumentation = this.instrumentation;
                ClassDefinition classDefinition = new ClassDefinition(classBeingRedefined, cc.toBytecode());
                System.out.println("Attempting to redefine class: " + className);
                try {
                    instrumentation.redefineClasses(classDefinition);
                    System.out.println("Class redefined successfully: " + className);
                } catch (Exception e) {
                    System.err.println("Failed to redefine class: " + className);
                    e.printStackTrace();
                }


                return null;


                //return cc.toBytecode(); // 返回修改后的字节码
            } catch (Exception e) {
                e.printStackTrace();
                return null; // 如果发生异常，返回原始字节码
            }
        }
        return null; // 如果不是目标包下的类，不进行任何操作
    }
    private void extractApiInfo(String className,ClassLoader loader) throws Exception {
        if (className.startsWith("org/javaweb/vuln/controller/")) {
            try {
                // 使用反射API获取类信息
                Class<?> clazz = Class.forName(className.replace('/', '.'), false, loader);

                // 创建一个Map来存储当前类的信息
                Map<String, Object> classInfo = new LinkedHashMap<>();
                //System.out.println("类名: " + clazz.getName());
                classInfo.put("className", clazz.getName());
                // 存储当前类的方法信息
                List<Map<String, Object>> apisInfo = new ArrayList<>();
                //classInfo.put("apis",apisInfo);
                RequestMapping classRequestMapping = clazz.getAnnotation(RequestMapping.class);
                String partApi = "";
                if (classRequestMapping != null) {
                    // 获取@RequestMapping注解的值
                    String[] classUrls = classRequestMapping.value();
                    //类上的部分url
                    partApi = Arrays.toString(classUrls).replace("[","").replace("]","");
                }

                // 获取并打印方法信息
                Method[] methods = clazz.getDeclaredMethods();
                for (Method method : methods) {
                    //System.out.println("方法: " + method.getName());
                    Map<String,Object> methodInfo = new HashMap<>();
                    methodInfo.put("methodName",method.getName());
                    RequestMapping requestMapping = method.getAnnotation(RequestMapping.class);
                    PostMapping postMapping = method.getAnnotation(PostMapping.class);
                    GetMapping getMapping = method.getAnnotation(GetMapping.class);
                    //---------------------------------------------------------------------------------
                    if (requestMapping != null) {
                        //得到方法请求方式
                        methodInfo.put("requestType","GET + POST");
                        // 获取@RequestMapping注解的值
                        String[] urls = requestMapping.value();
                        //方法上的api
                        String mainApi = Arrays.toString(urls).replace("[","").replace("]","");
                        String allApi = partApi + mainApi;
                        allApi = allApi.replace("//","/");
                        methodInfo.put("url",allApi);
                        String methodReturnType = getMethodReturnType(method);
                        methodInfo.put("returns",methodReturnType);
                        Parameter[] parameters = method.getParameters();
                        // --------------
                        Map<String,Object> params = getParamsAnnotation(method);
                        Map<String,Object> schema = new HashMap<>();
                        if(parameters.length == 0){
                            params.put("required","false");
                        }else {
                            params.put("required","true");
                            for (Parameter parameter : parameters) {
                                //params.put(parameter.getType().getSimpleName(), parameter.getName());
                                schema.put( parameter.getName(),getParamsType(parameter));
                            }
                        }
                        params.put("schema",schema);
                        methodInfo.put("params",params);
                        apisInfo.add(methodInfo);
                        //log(clazz,method);
                    } else if (postMapping != null) {
                        methodInfo.put("requestType","POST");
                        String[] urls = postMapping.value();
                        //方法上的api
                        String mainApi = Arrays.toString(urls).replace("[","").replace("]","");
                        String allApi = partApi + mainApi;
                        allApi = allApi.replace("//","/");
                        methodInfo.put("url",allApi);
                        String methodReturnType = getMethodReturnType(method);
                        methodInfo.put("returns",methodReturnType);
                        Parameter[] parameters = method.getParameters();


                        // --------------
                        Map<String,Object> params = getParamsAnnotation(method);
                        Map<String,Object> schema = new HashMap<>();
                        if(parameters.length == 0){
                            params.put("required","false");
                        }else {
                            params.put("required","true");
                            for (Parameter parameter : parameters) {
                                //params.put(parameter.getType().getSimpleName(), parameter.getName());
                                schema.put( parameter.getName(),getParamsType(parameter));
                            }
                        }
                        params.put("schema",schema);
                        methodInfo.put("params",params);
                        apisInfo.add(methodInfo);
                        //-------------------------------------------------------------------
                        //log(clazz,method);
                        //------------------------------------------------------------------
                    }else if (getMapping != null){
                        methodInfo.put("requestType","GET");
                        String[] urls = getMapping.value();
                        //方法上的api
                        String mainApi = Arrays.toString(urls).replace("[","").replace("]","");
                        String allApi = partApi + mainApi;
                        allApi = allApi.replace("//","/");
                        methodInfo.put("url",allApi);
                        String methodReturnType = getMethodReturnType(method);
                        methodInfo.put("returns",methodReturnType);
                        Parameter[] parameters = method.getParameters();
                        // --------------
                        Map<String,Object> params = getParamsAnnotation(method);
                        Map<String,Object> schema = new HashMap<>();
                        if(parameters.length == 0){
                            params.put("required","false");
                        }else {
                            params.put("required","true");
                            for (Parameter parameter : parameters) {
                                //params.put(parameter.getType().getSimpleName(), parameter.getName());
                                schema.put( parameter.getName(),getParamsType(parameter));
                            }
                        }
                        params.put("schema",schema);
                        methodInfo.put("params",params);
                        apisInfo.add(methodInfo);
                        //-------------------------------------------------------------------
                        //log(clazz,method);
                        //------------------------------------------------------------------
                    }
                }
                classInfo.put("methods",apisInfo);
                String jsonString = JSONObject.toJSONString(classInfo);
                write(jsonString,clazz.getName());

            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }

        }
    }

    private void enhanceMethods(CtClass ctClass) throws CannotCompileException {
        // 增强方法逻辑
        for (CtMethod method : ctClass.getDeclaredMethods()) {
            // 检查是否是需要增强的方法，比如通过注解或其他条件
            if ("getProcessBuilder".equals(method.getName())) {
                method.insertBefore("{ System.out.println(\"方法开始于: \" + new java.util.Date()); }");
                method.insertAfter(
                        "{ Object result = $_; System.out.println(\"方法结束于: \" + new java.util.Date());" +
                                "System.out.println(\"方法返回结果: \" + result);}",
                        true);
            }
        }
    }

    //日志操作
    private static void log(Class<?> clazz,Method method){
        //-------------------------------------------------------------------
        try {
            System.out.println("开始执行log--------------------------------------------------");
            ClassPool classPool = ClassPool.getDefault();
            CtClass ctClass = classPool.get(clazz.getName());
            CtMethod ctMethod = ctClass.getDeclaredMethod(method.getName());

            // 在方法执行后加入日志
            ctMethod.insertAfter("{System.out.println(\"Method " + method.getName() + " executed, return value: \" + $_);}");

            // 再次加载类
            ctClass.toClass();
        } catch (Exception e) {
            e.printStackTrace();
        }
        //------------------------------------------------------------------
    }
    //写入本地方法
    private static void write(String jsonString,String fileName){
        File directory = new File(FILE_PATH);
        if (!directory.exists()) {
            directory.mkdirs();
        }
        String filePath = FILE_PATH + fileName + ".txt";

        try (FileWriter fileWriter = new FileWriter(filePath);
             BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
            bufferedWriter.write(jsonString);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    //返回params的参数类型方法
    private static String getParamsType(Parameter parameter){
        Type type = parameter.getParameterizedType();
        return getTypeName(type);
    }

    //获得返回类型的方法
    public static String getMethodReturnType(Method method) {
        Type returnType = method.getGenericReturnType();
        return getTypeName(returnType);
    }

    private static String getTypeName(Type type) {
        if (type instanceof Class) {
            return ((Class<?>) type).getSimpleName();
        } else if (type instanceof ParameterizedType) {
            ParameterizedType parameterizedType = (ParameterizedType) type;
            Class<?> rawType = (Class<?>) parameterizedType.getRawType();
            Type[] typeArguments = parameterizedType.getActualTypeArguments();
            StringBuilder sb = new StringBuilder();
            sb.append(rawType.getSimpleName());
            sb.append("<");
            for (int i = 0; i < typeArguments.length; i++) {
                sb.append(getTypeName(typeArguments[i]));
                if (i < typeArguments.length - 1) {
                    sb.append(", ");
                }
            }
            sb.append(">");
            return sb.toString();
        } else if (type instanceof TypeVariable) {
            TypeVariable<?> typeVar = (TypeVariable<?>) type;
            return typeVar.getName();
        } else {
            return type.toString();
        }
    }

    private static Map<String,Object> getParamsAnnotation(Method method){
        java.lang.annotation.Annotation[] parameterAnnotation = method.getParameterAnnotations()[0];
        Map<String,Object> params = new HashMap<>();
        for (Annotation annotation : parameterAnnotation) {
            // 检查注解是否是@CookieValue
            if (annotation instanceof CookieValue) {
                CookieValue cookieValue = (CookieValue) annotation;
                // 获取@CookieValue注解的name属性
                String name = cookieValue.name();
                params.put("in","Cookie");
                params.put("name",name);
                System.out.println("CookieValue name: " + name);
            } else if (annotation instanceof RequestHeader) {
                RequestHeader cookieValue = (RequestHeader) annotation;
                // 获取@CookieValue注解的name属性
                String name = cookieValue.name();
                params.put("in","Header");
                params.put("name",name);
            } else if (annotation instanceof RequestBody) {
                RequestBody cookieValue = (RequestBody) annotation;
                params.put("in","Body");
                params.put("name","");
            }
        }
        return params;
    }
}

