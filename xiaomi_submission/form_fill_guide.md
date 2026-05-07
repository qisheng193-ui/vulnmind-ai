# 表单填写指南

## 04 可直接填写版本

我构建了一个面向源码仓库的 AI 安全审计 Agent，项目名称为 VulnMind AI Secure Code Review Agent。它主要解决研发团队在代码上线前缺少高效安全巡检能力的问题，能够自动遍历 PHP、Python、JavaScript 仓库，识别动态执行、命令执行、不安全反序列化、动态文件包含等高风险调用点，并输出结构化风险报告、验证建议和修复建议。

核心逻辑采用多 Agent 协作方式：ReconAgent 负责源码解析和攻击面发现，TriageAgent 负责风险分级与置信度判断，GuidanceAgent 负责生成验证与修复建议，ReportAgent 负责输出文本、Markdown 和 JSON 报告。当前已经完成可运行的项目化封装、命令行调用、报告生成、测试验证和提交材料整理，可用于企业研发团队的 DevSecOps、安全左移和代码上线前巡检场景。

## 04 更短版本

我构建了一个正式可运行的 AI 安全审计 Agent，用于帮助研发团队在代码上线前自动扫描源码仓库中的高风险调用点。项目支持 PHP、Python、JavaScript 仓库扫描，能够识别动态执行、命令执行、不安全反序列化等风险，并自动生成风险分级、验证建议和修复建议。

核心逻辑采用多 Agent 协作：ReconAgent 负责源码解析与风险发现，TriageAgent 负责风险判断，GuidanceAgent 负责修复建议生成，ReportAgent 负责输出结构化审计报告。当前已完成项目化封装、报告导出、测试验证与演示材料整理，适用于企业 DevSecOps 与安全左移场景。

## 05 建议上传的材料

建议优先传这 4 个：

1. 项目运行截图
2. 终端执行截图
3. 生成的 Markdown 报告截图
4. 1 分钟以内录屏

建议配套链接：

- GitHub 项目链接
- 如果没有在线演示，就填 GitHub 仓库地址

## GitHub 仓库建议命名

- `vulnmind-ai`
- `vulnmind-secure-code-review-agent`

## 可放进仓库首页的简短介绍

VulnMind AI is an AI-assisted secure code review agent for source repositories. It helps development teams detect risky code patterns, prioritize findings, and generate remediation guidance before release.
