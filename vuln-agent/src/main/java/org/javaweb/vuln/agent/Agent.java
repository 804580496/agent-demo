package org.javaweb.vuln.agent;


import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
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


    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new ClassTransformer(),true);

    }


}


