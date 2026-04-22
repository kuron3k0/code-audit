# 动态代码审计指南 (Dynamic Code Audit Guide)

> LSP 无法覆盖的场景及其解决方案
> 核心原则：静态分析的盲区需要模式匹配 + 人工验证的组合策略

---

## 概述

LSP 依赖编译期类型信息进行语义分析，对于以下场景存在天然盲区：

| 盲区类型 | 原因 | 风险等级 | 解决策略 |
|----------|------|----------|----------|
| 反射调用 | 运行时确定类/方法 | 🔴 高 | Grep + 反射审计矩阵 |
| 动态方法名 | 字符串拼接确定调用 | 🔴 高 | 污点追踪 + 人工分析 |
| 配置驱动 | 配置文件指定类名 | 🟡 中 | 配置解析 + 代码映射 |
| 运行时加载 | ClassLoader/import | 🔴 高 | 来源审计 + 沙箱检查 |
| AOP/代理 | 切面拦截修改行为 | 🟡 中 | 切面清单 + 影响分析 |
| 异步回调 | 消息队列/Future | 🟡 中 | 追踪处理器 |

---

## 1. 反射调用审计

### 1.1 Java 反射检测命令

```bash
# 一键扫描所有反射入口点
grep -rn "Class\.forName\|\.getMethod\|\.getDeclaredMethod\|\.invoke\|\.newInstance\|Constructor\.newInstance" --include="*.java"

# 分类扫描
# 类加载
grep -rn "Class\.forName\|ClassLoader\|loadClass" --include="*.java"

# 方法调用
grep -rn "Method\.invoke\|\.getMethod\|\.getDeclaredMethod" --include="*.java"

# 实例化
grep -rn "\.newInstance\|Constructor\.newInstance" --include="*.java"

# 字段访问
grep -rn "Field\.get\|Field\.set\|\.getDeclaredField" --include="*.java"
```

### 1.2 Python 反射检测命令

```bash
# 动态属性访问
grep -rn "getattr\|setattr\|hasattr\|__getattr__\|__getattribute__" --include="*.py"

# 动态导入
grep -rn "importlib\.import_module\|__import__\|exec\|eval\|compile" --include="*.py"

# 类型操作
grep -rn "type(\|isinstance\|issubclass\|__class__" --include="*.py"
```

### 1.3 JavaScript/Node.js 反射检测

```bash
# 动态属性访问
grep -rn "\[.*\]\s*(\|\[.*\]\s*=" --include="*.js" --include="*.ts"

# 动态执行
grep -rn "eval\|Function\s*(\|new\s*Function\|setTimeout.*string\|setInterval.*string" --include="*.js" --include="*.ts"

# 动态导入
grep -rn "require\s*(\s*[^'\"]" --include="*.js"
grep -rn "import\s*(\s*[^'\"]" --include="*.js" --include="*.ts"
```

### 1.4 反射风险评估矩阵

```
┌─────────────────────────────────────────────────────────────────┐
│                    反射参数来源评估                              │
├─────────────────┬───────────────┬───────────────┬───────────────┤
│ 来源            │ 风险等级      │ 利用难度      │ 处置建议      │
├─────────────────┼───────────────┼───────────────┼───────────────┤
│ 用户输入直接    │ 🔴 严重       │ 低            │ 立即修复      │
│ HTTP参数/Header │ 🔴 严重       │ 低            │ 立即修复      │
│ 数据库查询结果  │ 🟠 高         │ 中            │ 需要2次注入   │
│ 配置文件        │ 🟡 中         │ 高            │ 检查配置权限  │
│ 硬编码字符串    │ 🟢 低         │ N/A           │ 可接受        │
│ 白名单校验后    │ 🟢 低         │ N/A           │ 验证白名单    │
└─────────────────┴───────────────┴───────────────┴───────────────┘
```

### 1.5 反射审计检查清单

```markdown
□ 1. 反射参数来源追踪
  - 参数是否来自用户输入？
  - 参数是否经过白名单校验？
  - 参数是否来自可信配置？

□ 2. 类名/方法名白名单检查
  - 是否限制可加载的类？
  - 是否限制可调用的方法？
  - 白名单是否完整（无遗漏）？

□ 3. 危险类黑名单检查
  - Runtime, ProcessBuilder (命令执行)
  - URLClassLoader (远程类加载)
  - ScriptEngine (脚本执行)
  - JNDI相关类 (JNDI注入)

□ 4. 安全管理器检查
  - 是否配置SecurityManager？
  - 反射权限是否受限？
```

---

## 2. 动态方法名追踪

### 2.1 模式识别

```bash
# Java - 字符串拼接后反射
grep -rn "getMethod.*\+" --include="*.java"
grep -rn "getDeclaredMethod.*\+" --include="*.java"

# Python - 动态属性访问
grep -rn "getattr.*\+" --include="*.py"
grep -rn "getattr.*format\|getattr.*%" --include="*.py"

# JavaScript - 动态属性
grep -rn "\[.*\+.*\]" --include="*.js" --include="*.ts"
```

### 2.2 污点追踪策略

```
动态方法名审计流程:

1. 识别动态调用点
   grep -rn "getattr\|getMethod\|\[.*\]("

2. 向上追踪方法名来源
   - 是变量？→ 继续追踪变量赋值
   - 是函数返回值？→ 分析函数逻辑
   - 是字符串拼接？→ 追踪各组成部分

3. 判断污点源
   - 用户输入 → 高危
   - 配置文件 → 中危
   - 硬编码 → 低危

4. 检查净化措施
   - 白名单校验？
   - 正则校验？
   - 类型限制？
```

### 2.3 危险模式示例

```java
// 🔴 高危 - 用户输入直接用于方法名
String methodName = request.getParameter("action");
Method method = clazz.getMethod(methodName);
method.invoke(instance);

// 🟡 中危 - 拼接但部分可控
String methodName = "handle" + request.getParameter("type");
Method method = clazz.getMethod(methodName);

// 🟢 低危 - 白名单校验
String action = request.getParameter("action");
if (ALLOWED_ACTIONS.contains(action)) {
    Method method = clazz.getMethod(action);
}
```

---

## 3. 配置驱动的类加载

### 3.1 配置文件类型扫描

```bash
# Spring XML 配置
grep -rn "class=\"\${" --include="*.xml"
grep -rn "<bean.*class=" --include="*.xml"

# YAML/Properties 配置
grep -rn "className\|class-name\|handler\|processor\|factory" --include="*.yml" --include="*.yaml" --include="*.properties"

# JSON 配置
grep -rn "\"class\"\|\"className\"\|\"type\"" --include="*.json"
```

### 3.2 配置到代码映射脚本

```bash
#!/bin/bash
# 配置类名提取与代码映射

echo "=== 从配置提取类名 ==="
# Spring XML
grep -ohP 'class="[^"$][^"]*"' **/*.xml 2>/dev/null | sort -u

# YAML
grep -ohP 'class:\s*\K[^\s]+' **/*.yml **/*.yaml 2>/dev/null | sort -u

echo "=== 验证类是否存在 ==="
# 提取的类名与代码比对
for class in $(grep -ohP 'class="([^"$]+)"' **/*.xml | grep -oP '(?<=class=")[^"]+'); do
    file=$(echo $class | tr '.' '/' | sed 's/$/.java/')
    if [ -f "src/main/java/$file" ]; then
        echo "✓ $class"
    else
        echo "✗ $class (未找到源码)"
    fi
done
```

### 3.3 Spring Bean 配置审计

```bash
# 查找 PropertyPlaceholder 配置的类
grep -rn "PropertyPlaceholderConfigurer\|\$\{.*class" --include="*.xml"

# 检查外部化配置
grep -rn "@Value.*class\|@ConfigurationProperties" --include="*.java"

# 动态 Bean 注册
grep -rn "BeanDefinitionRegistry\|registerBeanDefinition" --include="*.java"
```

---

## 4. 运行时动态加载

### 4.1 类加载器审计

```bash
# Java ClassLoader
grep -rn "URLClassLoader\|defineClass\|loadClass\|ClassLoader\.getSystemClassLoader" --include="*.java"

# 远程类加载（高危）
grep -rn "new URL.*\.jar\|URLClassLoader.*http\|URLClassLoader.*ftp" --include="*.java"

# 自定义类加载器
grep -rn "extends ClassLoader\|extends URLClassLoader" --include="*.java"
```

### 4.2 Python 动态导入

```bash
# importlib 使用
grep -rn "importlib\.import_module\|__import__" --include="*.py"

# exec/eval 执行代码
grep -rn "exec\s*(\|eval\s*(" --include="*.py"

# 模块路径操作
grep -rn "sys\.path\.append\|sys\.path\.insert" --include="*.py"
```

### 4.3 Node.js 动态 require

```bash
# 动态 require
grep -rn "require\s*(\s*[^'\"\`]" --include="*.js"

# vm 模块（沙箱逃逸风险）
grep -rn "require.*vm\|vm\.runIn\|vm\.Script" --include="*.js"

# child_process 动态执行
grep -rn "child_process\|spawn\|exec\|execSync" --include="*.js"
```

### 4.4 运行时加载风险清单

```markdown
□ 加载来源检查
  - 是否从远程URL加载？→ 高危
  - 是否从用户可控路径加载？→ 高危
  - 是否从受信任目录加载？→ 需验证目录权限

□ 加载内容验证
  - 是否验证签名/哈希？
  - 是否有完整性校验？
  - 是否限制可加载的类/模块？

□ 沙箱机制
  - 是否在受限环境执行？
  - SecurityManager 是否配置？
  - 文件/网络权限是否受限？
```

---

## 5. AOP/代理/装饰器审计

### 5.1 Spring AOP 审计

```bash
# 切面定义
grep -rn "@Aspect\|@Around\|@Before\|@After\|@AfterReturning\|@AfterThrowing" --include="*.java"

# 切点表达式
grep -rn "@Pointcut\|execution\s*(\|within\s*(" --include="*.java"

# 动态代理
grep -rn "Proxy\.newProxyInstance\|InvocationHandler\|CGLib\|ByteBuddy" --include="*.java"
```

### 5.2 Python 装饰器审计

```bash
# 装饰器定义
grep -rn "^@\|def\s+\w+.*wrapper" --include="*.py"

# 动态装饰
grep -rn "functools\.wraps\|functools\.partial" --include="*.py"

# 元类
grep -rn "__metaclass__\|metaclass=" --include="*.py"
```

### 5.3 AOP 影响分析检查表

```markdown
□ 1. 切面清单
  - 列出所有 @Aspect 类
  - 每个切面的切点范围
  - 切面执行顺序 (@Order)

□ 2. 安全相关切面
  - 认证切面是否覆盖所有入口？
  - 授权切面逻辑是否正确？
  - 日志切面是否记录敏感数据？

□ 3. 切面绕过风险
  - 是否存在不经过切面的调用路径？
  - 内部方法调用是否被切面拦截？
  - 异常情况下切面是否仍生效？
```

---

## 6. 消息队列/异步回调

### 6.1 消息队列审计

```bash
# Kafka
grep -rn "@KafkaListener\|KafkaTemplate\|ConsumerRecord" --include="*.java"

# RabbitMQ
grep -rn "@RabbitListener\|RabbitTemplate\|@Queue" --include="*.java"

# Redis Pub/Sub
grep -rn "RedisMessageListenerContainer\|MessageListener\|subscribe" --include="*.java"

# 通用消息
grep -rn "MessageListener\|onMessage\|handleMessage" --include="*.java"
```

### 6.2 异步回调审计

```bash
# CompletableFuture
grep -rn "CompletableFuture\|thenApply\|thenAccept\|thenCompose" --include="*.java"

# Callback 模式
grep -rn "Callback\|onSuccess\|onFailure\|onComplete" --include="*.java"

# RxJava/Reactor
grep -rn "subscribe\|onNext\|onError\|flatMap" --include="*.java"

# Node.js Promise/async
grep -rn "\.then\|\.catch\|async\s+function\|await" --include="*.js" --include="*.ts"
```

### 6.3 消息反序列化风险

```markdown
□ 消息格式检查
  - JSON 消息 → 检查 Fastjson/Jackson 配置
  - 二进制消息 → 检查反序列化方式
  - XML 消息 → 检查 XXE 防护

□ 消息来源验证
  - 消息是否来自可信生产者？
  - 是否验证消息签名？
  - 是否有消息内容校验？

□ 处理器安全
  - 处理器是否有异常处理？
  - 失败消息如何处理（DLQ）？
  - 是否有速率限制？
```

---

## 7. Semgrep 规则补充

当 LSP 不可用或需要批量扫描时，使用 Semgrep 规则：

### 7.1 Java 反射规则

```yaml
# semgrep-reflection.yaml
rules:
  - id: java-reflection-user-input
    patterns:
      - pattern-either:
          - pattern: Class.forName($USER_INPUT)
          - pattern: $CLS.getMethod($USER_INPUT, ...)
          - pattern: $CLS.getDeclaredMethod($USER_INPUT, ...)
      - pattern-inside: |
          ... $REQUEST.getParameter(...) ...
    message: "反射参数来自用户输入，可能导致RCE"
    severity: ERROR
    languages: [java]

  - id: java-unsafe-invoke
    pattern: $METHOD.invoke($OBJ, $ARGS)
    message: "检测到 Method.invoke，需验证方法来源"
    severity: WARNING
    languages: [java]
```

### 7.2 Python 动态执行规则

```yaml
# semgrep-python-dynamic.yaml
rules:
  - id: python-eval-user-input
    patterns:
      - pattern-either:
          - pattern: eval($INPUT)
          - pattern: exec($INPUT)
      - pattern-inside: |
          ... request.$METHOD(...) ...
    message: "eval/exec 参数来自用户输入"
    severity: ERROR
    languages: [python]

  - id: python-getattr-dynamic
    pattern: getattr($OBJ, $USER_INPUT)
    message: "动态属性访问，需验证属性名来源"
    severity: WARNING
    languages: [python]
```

### 7.3 运行 Semgrep 扫描

```bash
# 安装 Semgrep
pip install semgrep

# 使用自定义规则扫描
semgrep --config=semgrep-reflection.yaml /path/to/code

# 使用官方规则集
semgrep --config=p/java /path/to/code
semgrep --config=p/python /path/to/code

# 输出JSON格式
semgrep --config=semgrep-reflection.yaml --json /path/to/code
```

---

## 8. 审计流程整合

### 8.1 完整审计流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    动态代码审计流程                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. LSP 语义分析                                                │
│     ├─ goToDefinition 追踪数据流                               │
│     ├─ findReferences 找所有调用点                             │
│     └─ incomingCalls 分析调用链                                │
│              │                                                  │
│              ▼                                                  │
│  2. 识别 LSP 盲区                                               │
│     ├─ 反射调用 → 本指南 §1                                    │
│     ├─ 动态方法名 → 本指南 §2                                  │
│     ├─ 配置驱动 → 本指南 §3                                    │
│     ├─ 运行时加载 → 本指南 §4                                  │
│     ├─ AOP/代理 → 本指南 §5                                    │
│     └─ 异步回调 → 本指南 §6                                    │
│              │                                                  │
│              ▼                                                  │
│  3. Grep + Semgrep 补充扫描                                    │
│     ├─ 执行本指南中的检测命令                                   │
│     ├─ 运行 Semgrep 自定义规则                                 │
│     └─ 标记所有可疑点                                          │
│              │                                                  │
│              ▼                                                  │
│  4. 人工验证                                                    │
│     ├─ 追踪参数来源                                            │
│     ├─ 验证净化措施                                            │
│     └─ 评估利用可行性                                          │
│              │                                                  │
│              ▼                                                  │
│  5. 风险评估与报告                                              │
│     ├─ 使用风险矩阵评级                                        │
│     └─ 输出结构化报告                                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 快速检测命令汇总

```bash
# 一键扫描所有动态代码风险点
echo "=== Java 反射 ===" && \
grep -rn "Class\.forName\|\.invoke\|\.newInstance" --include="*.java" && \
echo "=== Python 动态 ===" && \
grep -rn "eval\|exec\|getattr\|__import__" --include="*.py" && \
echo "=== JS 动态 ===" && \
grep -rn "eval\|Function\s*(\|require\s*([^'\"]" --include="*.js" && \
echo "=== 配置类名 ===" && \
grep -rn "class=\"\${" --include="*.xml" && \
echo "=== 类加载器 ===" && \
grep -rn "ClassLoader\|URLClassLoader\|loadClass" --include="*.java"
```

---

## 9. 报告模板

````markdown
## 动态代码风险点: [编号]

### 基本信息
- **文件**: [文件路径:行号]
- **类型**: [反射/动态方法/配置驱动/运行时加载/AOP/异步]
- **风险等级**: [严重/高/中/低]

### 代码片段
```[语言]
[相关代码]
```

### 数据流分析
- **输入源**: [用户输入/配置文件/数据库/硬编码]
- **数据流**: [Source] → [Transform] → [Sink]
- **净化措施**: [白名单/正则/无]

### 利用分析
- **可利用性**: [是/否/需要进一步分析]
- **利用条件**: [描述前置条件]
- **潜在影响**: [RCE/信息泄露/权限绕过/...]

### 修复建议
1. [具体修复建议]
2. [替代方案]
````


---

**版本**: 1.0
**创建日期**: 2026-02-04
**关联文档**: TOOLS.md §1.5 LSP 语义分析工具
