package org.javaweb.vuln.agent;


import com.alibaba.fastjson.JSONObject;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.*;
import java.security.ProtectionDomain;
import java.util.*;

/**
 * ClassName: Agent
 * Package: org.javaweb.vuln.agent
 * Description:
 *
 * @Author DYH
 * @Create 2025/3/6
 * @Version 1.0
 */
public class Agent {

    // 定义一个全局的List来存储所有类信息
    public static final List<Map<String, Object>>classList = new ArrayList<>();

    //可替换地址
    public static String LOCAL_HOST = "http://localhost:8003/";

    //文件路径D:\apis\
    public static String FILE_PATH = "D:\\apis\\";


    public static void premain(String agentArgs, Instrumentation inst) {

        System.out.println("-------------------------------------------------agent启动-----------------------------------------------------------");

        inst.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                //替换packageName，可检测不同包下的api
                getApi(className,loader,"org/javaweb/vuln/controller/");
                // 返回null表示不修改类文件
                return null;
            }
        });



    }

    //类加载前
    private static void getApi(String className,ClassLoader loader,String packageName){
        if (className.startsWith(packageName)) {
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
                        log(clazz,method);
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
                        log(clazz,method);
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
                       log(clazz,method);
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
        Annotation[] parameterAnnotation = method.getParameterAnnotations()[0];
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


