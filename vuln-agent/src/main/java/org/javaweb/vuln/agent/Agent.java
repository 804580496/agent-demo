package org.javaweb.vuln.agent;



import java.lang.instrument.Instrumentation;


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
    private static Instrumentation instrumentation;



    public static void premain(String agentArgs, Instrumentation inst) {

        System.out.println("-------------------------------------------------agent启动-----------------------------------------------------------");



        inst.addTransformer(new MethodTimerTransformer(), true);
        //inst.addTransformer(new ClassTransformer(),true);
        //inst.addTransformer(new ClassAndMethodTransformer(inst),true);



    }









}


