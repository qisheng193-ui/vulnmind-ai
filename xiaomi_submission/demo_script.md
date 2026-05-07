# 演示脚本

## 30 秒版本

1. 选择一个示例源码目录。
2. 运行 VulnMind AI 扫描。
3. 展示生成的 Markdown 报告。
4. 指出定位结果、风险等级和修复建议。

## 90 秒版本

1. 说明项目定位：这是一个面向研发团队的 AI 安全审计 Agent。
2. 选择包含 PHP 或 Python 风险调用的测试目录。
3. 执行：

```bash
python -m vulnmind_ai "D:\demo_repo" --output-dir reports
```

4. 展示输出的 `vulnmind_report.md`。
5. 重点介绍：
   - Agent 自动遍历仓库
   - 自动识别高风险模式
   - 自动生成验证与修复建议
6. 补一句平台化价值：
   - 可以作为企业内部代码准入前的一道轻量安全检查
