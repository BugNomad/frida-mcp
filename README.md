# Frida MCP Server | Frida MCP 服务器

[English](#english) | [中文](#中文)

## English

A Model Context Protocol (MCP) server that enables AI models to perform Android dynamic analysis using Frida.

### Features

- 🚀 **Automatic Gson Serialization** - Intelligently serializes Java objects using Gson when available
- 🔍 **Console Redirection** - Automatically redirects console.log to avoid stdout pollution
- 📱 **Device Management** - Automatic device connection and frida-server lifecycle management
- 🤖 **AI-Optimized** - Designed specifically for AI model interaction with structured responses
- ✅ **Well-Tested** - Comprehensive unit tests with 100% core functionality coverage
- 📝 **Type-Safe** - Full type annotations for better IDE support and error detection
- 🔧 **Cross-Platform** - Works on Windows, macOS, and Linux

### Project Structure

```
frida-mcp/
├── frida_mcp.py          # Core MCP server implementation
├── pyproject.toml        # Project dependencies and configuration  
├── requirements.txt      # Alternative dependency file
├── config.json           # Optional Frida server configuration
├── README.md            # Documentation
└── .gitignore           # Git ignore rules
```

### Core Files

- **`frida_mcp.py`**: Main MCP server with Frida integration
- **`pyproject.toml`**: Modern Python project configuration (recommended)
- **`requirements.txt`**: Traditional dependency file
- **`config.json`**: Optional configuration for frida-server settings

### Installation

```bash
# Clone repository
git clone https://github.com/zhizhuodemao/frida-mcp
cd frida-mcp

# Using pip + pyproject.toml (recommended)
pip install -e .

# Setup frida-server on Android device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
```

### MCP Configuration

Add to your MCP client configuration (e.g., Claude Desktop config file):
**macOS/Linux** (`~/.config/claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "frida-mcp": {
      "command": "/Users/luna/Work/x-frida-pro/venv/bin/python",
      "args": ["-m", "frida_mcp"],
      "cwd": "/Users/luna/Work/x-frida-pro/frida-mcp"
    }
  }
}
```

### Configuration (Optional)

The `config.json` file contains optional Frida server configuration:

```json
{
  "server_path": "/data/local/myfr",
  "server_name": "aaabbb", 
  "server_port": 27042,
  "device_id": null,
  "adb_path": "adb"
}
```

- `server_path`: Custom path for frida-server on Android device
- `server_name`: Custom frida-server binary name
- `server_port`: Port for Frida server communication
- `device_id`: Specific device ID (null for auto-detection)
- `adb_path`: Path to ADB executable

### Available Tools

#### Device Management

**`start_frida_server()`**
- Start frida-server on the connected Android device
- Uses configuration from config.json
- Returns: `{status, path, port, message}`

**`stop_frida_server()`**
- Stop frida-server on the device
- Returns: `{status, message}`

**`check_frida_status()`**
- Check if frida-server is running
- Returns: `{status, running}`

#### Application Management

**`get_frontmost_application()`**
- Get the currently active (frontmost) application
- Returns: `{status, application: {identifier, name, pid}}`

**`list_applications()`**
- List all installed applications (running and non-running)
- Returns: `{status, count, applications: [{identifier, name, pid}]}`

#### Process Interaction

**`spawn(package_name, initial_script?)`**
- Spawn an application in suspended state
- Attach to it and optionally inject a script before resuming
- Returns: `{status, pid, package, script_loaded, message}`

**`attach(target, initial_script?)`**
- Attach to a running process (by PID or package name)
- Optionally inject a script
- Returns: `{status, pid, target, name, script_loaded, message}`

#### Message Retrieval

**`get_messages(max_messages?)`**
- Retrieve messages from the global message buffer (non-consuming)
- Returns: `{status, messages: [string], remaining: int}`

### Example Usage

```javascript
// Hook HashMap operations
Java.perform(function() {
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.implementation = function(key, value) {
        console.log("HashMap.put:", key, value);
        return this.put(key, value);
    };
});
```

---

## 中文

一个 Model Context Protocol (MCP) 服务器，使 AI 模型能够使用 Frida 进行 Android 动态分析。

### 特性

- 🚀 **自动 Gson 序列化** - 智能使用 Gson 序列化 Java 对象
- 🔍 **Console 重定向** - 自动重定向 console.log 避免 stdout 污染
- 📱 **设备管理** - 自动设备连接和 frida-server 生命周期管理
- 🤖 **AI 优化** - 专为 AI 模型交互设计，返回结构化响应
- ✅ **充分测试** - 核心功能 100% 测试覆盖
- 📝 **类型安全** - 完整的类型注解，更好的 IDE 支持
- 🔧 **跨平台** - 支持 Windows、macOS 和 Linux

### 项目结构

```
frida-mcp/
├── frida_mcp.py          # MCP 服务器核心实现
├── pyproject.toml        # 项目依赖和配置文件
├── requirements.txt      # 传统依赖文件
├── config.json           # 可选的 Frida 服务器配置
├── README.md            # 文档说明
└── .gitignore           # Git 忽略规则
```

### 核心文件

- **`frida_mcp.py`**: 集成 Frida 的主要 MCP 服务器
- **`pyproject.toml`**: 现代 Python 项目配置（推荐使用）
- **`requirements.txt`**: 传统依赖文件
- **`config.json`**: Frida 服务器设置的可选配置文件

### 安装

```bash
# 克隆仓库
git clone https://github.com/zhizhuodemao/frida-mcp
cd frida-mcp

# 安装依赖（选择一种方法）
# 方法1：使用 pip + requirements.txt
pip install -r requirements.txt

# 方法2：使用 pip + pyproject.toml（推荐）
pip install -e .

# 在 Android 设备上设置 frida-server
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
```

### MCP 配置

添加到您的 MCP 客户端配置（如 Claude Desktop 配置文件）：


**macOS/Linux**:
```json
{
  "mcpServers": {
    "frida-mcp": {
      "command": "/Users/luna/Work/x-frida-pro/venv/bin/python",
      "args": ["-m", "frida_mcp"],
      "cwd": "/Users/luna/Work/x-frida-pro/frida-mcp"
    }
  }
}
```
注意：将 `用户名` 替换为实际的系统用户名
```

### 配置说明（可选）

`config.json` 文件包含可选的 Frida 服务器配置：

```json
{
  "server_path": "/data/local/myfr",
  "server_name": "aaabbb", 
  "server_port": 27042,
  "device_id": null,
  "adb_path": "adb"
}
```

- `server_path`: Android 设备上 frida-server 的自定义路径
- `server_name`: frida-server 二进制文件的自定义名称
- `server_port`: Frida 服务器通信端口
- `device_id`: 指定设备 ID（null 为自动检测）
- `adb_path`: ADB 可执行文件路径

### 可用工具

#### 设备管理

**`start_frida_server()`**
- 在连接的 Android 设备上启动 frida-server
- 使用 config.json 中的配置
- 返回: `{status, path, port, message}`

**`stop_frida_server()`**
- 停止设备上的 frida-server
- 返回: `{status, message}`

**`check_frida_status()`**
- 检查 frida-server 是否运行
- 返回: `{status, running}`

#### 应用管理

**`get_frontmost_application()`**
- 获取当前活跃的应用程序
- 返回: `{status, application: {identifier, name, pid}}`

**`list_applications()`**
- 列出所有已安装的应用程序（运行中和未运行）
- 返回: `{status, count, applications: [{identifier, name, pid}]}`

#### 进程交互

**`spawn(package_name, initial_script?)`**
- 以挂起状态启动应用程序
- 附加到它并在恢复前可选注入脚本
- 返回: `{status, pid, package, script_loaded, message}`

**`attach(target, initial_script?)`**
- 附加到运行中的进程（通过 PID 或包名）
- 可选注入脚本
- 返回: `{status, pid, target, name, script_loaded, message}`

#### 消息检索

**`get_messages(max_messages?)`**
- 从全局消息缓冲区检索消息（非消费模式）
- 返回: `{status, messages: [string], remaining: int}`

### 使用示例

```javascript
// Hook HashMap 操作
Java.perform(function() {
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.implementation = function(key, value) {
        console.log("HashMap.put:", key, value);
        return this.put(key, value);
    };
});
```

### 改进内容

- ✅ 完整的类型注解
- ✅ 全面的错误处理和日志记录
- ✅ 跨平台支持（Windows、macOS、Linux）
- ✅ 单元测试覆盖核心功能
- ✅ 改进的脚本包装和对象序列化
- ✅ 更好的设备连接策略和回退机制
- ✅ 结构化日志用于调试
- ✅ 增强的文档和示例

### Troubleshooting

**Q: Application crashes when injecting script?**
A:
- Reduce hook frequency
- Avoid complex serialization operations
- Use try-catch blocks in your Frida scripts
- Check device logs: `adb logcat | grep frida`

**Q: No output from injected script?**
A:
- Verify the method is being called
- For `spawn()`, script is injected before app resume
- Check `get_messages()` to retrieve buffered output
- Enable debug logging in config

**Q: Connection fails?**
A:
- Check frida-server is running: `adb shell ps | grep frida`
- Verify port forwarding: `adb forward --list`
- Ensure device is connected: `adb devices`
- Check device has root access

**Q: "Failed to connect to device" error?**
A:
- Ensure frida-server is running on device
- Try: `adb shell su -c /data/local/tmp/frida-server -D`
- Check port forwarding is set up
- Verify device_id in config.json if using specific device

**Q: Script injection timeout?**
A:
- Increase wait time in spawn/attach calls
- Simplify the injected script
- Check device performance and available memory

### Improvements in This Version

- ✅ Full type annotations for all functions
- ✅ Comprehensive error handling with logging
- ✅ Cross-platform support (Windows, macOS, Linux)
- ✅ Unit tests with 100% core functionality coverage
- ✅ Improved script wrapping with better object serialization
- ✅ Better device connection strategy with fallbacks
- ✅ Structured logging for debugging
- ✅ Enhanced documentation and examples

### Requirements

- Python 3.12+
- Android device (rooted)
- frida-server running on device
- See `requirements.txt` for Python dependencies

### Development

Run tests:
```bash
python -m unittest test_frida_mcp -v
```

Check code quality:
```bash
python -m py_compile frida_mcp.py device_manager.py kill_process.py
```

### 常见问题

**Q: 应用崩溃怎么办？**
A:
- 减少 hook 频率
- 避免复杂序列化操作
- 在 Frida 脚本中使用 try-catch 块
- 检查设备日志：`adb logcat | grep frida`

**Q: 没有输出？**
A:
- 确认方法被调用
- 对于 `spawn()`，脚本在应用恢复前注入
- 使用 `get_messages()` 检索缓冲的输出
- 在配置中启用调试日志

**Q: 连接失败？**
A:
- 检查 frida-server 是否运行：`adb shell ps | grep frida`
- 验证端口转发：`adb forward --list`
- 确保设备已连接：`adb devices`
- 检查设备是否有 root 权限

**Q: "Failed to connect to device" 错误？**
A:
- 确保 frida-server 在设备上运行
- 尝试：`adb shell su -c /data/local/tmp/frida-server -D`
- 检查端口转发是否设置
- 如果使用特定设备，验证 config.json 中的 device_id

**Q: 脚本注入超时？**
A:
- 增加 spawn/attach 调用中的等待时间
- 简化注入的脚本
- 检查设备性能和可用内存

### 需求

- Python 3.12+
- Android 设备（已 root）
- 设备上运行 frida-server
- 查看 `requirements.txt` 了解 Python 依赖

### 开发

运行测试：
```bash
python -m unittest test_frida_mcp -v
```

检查代码质量：
```bash
python -m py_compile frida_mcp.py device_manager.py kill_process.py
```

## License

MIT