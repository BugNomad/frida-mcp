# CLAUDE 工作规则

## 重要规则

### ⚠️ 代码修改权限
**除非用户明确要求修改代码，否则不准修改任何代码。**

- 只有在用户明确说"修改代码"、"改一下"、"fix"等明确指令时才能修改
- 分析问题、提出建议、解释原理时，不要主动修改代码
- 当不确定用户意图时，先询问是否需要修改代码

### 项目信息

**项目名称**: Frida MCP Server  
**主要文件**: frida_mcp.py  
**用途**: MCP协议的Frida动态分析工具，供其他大模型调用

### 技术约定

#### MCP协议相关
- 使用FastMCP框架
- 默认stdio传输协议
- **注意**: stdio不支持服务器主动通知，避免stdout污染
- 所有返回值必须是有效的JSON格式

#### Frida相关  
- 支持Android应用动态分析
- 主要工具：spawn、attach、hook_method、hook_function
- 全局状态管理：device、session

### 常见问题

#### JSON解析错误
- 原因：stdout被非JSON内容污染
- 解决：移除所有print语句，避免直接输出
- 检查：确保所有输出都通过MCP协议格式化

#### 长期运行输出
- stdio模式下无法实时推送
- 考虑切换到StreamableHTTP或使用轮询机制

### 调试指南

1. **协议错误**: 检查stdout污染源
2. **连接问题**: 确认frida-server运行状态  
3. **脚本错误**: 检查JavaScript语法和Frida API使用

---
*最后更新: 2025-01-24*