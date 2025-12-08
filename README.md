# httpcap

一个简单的 HTTP 抓包工具，用于捕获和分析 HTTP 流量。

## 功能特性

- 捕获 HTTP 协议数据包（端口 80）
- 支持源地址和目标地址过滤
- 支持 URI 过滤
- 可设置最大抓包数量，避免内存溢出
- 实时显示 HTTP 请求和响应

## 安装

### 前置要求

1. **安装 libpcap**

   macOS:
   ```bash
   brew install libpcap
   ```

   Linux (Ubuntu/Debian):
   ```bash
   sudo apt-get install libpcap-dev
   ```

   Linux (CentOS/RHEL):
   ```bash
   sudo yum install libpcap-devel
   ```

2. **安装 Go** (版本 1.21 或更高)

### 编译安装

```bash
cd httpcap
go mod download
go build -o httpcap
env GOOS=linux GOARCH=amd64 go build -o httpcap-linux-amd64
```

## 使用说明

### 查看可用网络接口

```bash
sudo ./httpcap -l
```

### 基本用法

```bash
sudo ./httpcap -i <网络接口>
```

### 命令行参数

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `-i` | 网络接口（必需） | - | `-i en0` |
| `-src` | 源地址过滤 | - | `-src 192.168.1.100` |
| `-dst` | 目标地址过滤，多个值用逗号分隔 | - | `-dst 10.0.0.1:80,10.0.0.2:80` |
| `-uri` | URI 过滤（包含匹配） | - | `-uri /api/users` |
| `-n` | 最大抓包数量 | 10 | `-n 50` |
| `-l` | 列出所有网络接口 | - | `-l` |

### 使用示例

1. **抓取所有 HTTP 流量（最多 10 个包）**
   ```bash
   sudo ./httpcap -i en0
   ```

2. **抓取本地回环流量（127.0.0.1）**
   ```bash
   # macOS
   sudo ./httpcap -i lo0 -dst 127.0.0.1:3000
   
   # Linux
   sudo ./httpcap -i lo -dst 127.0.0.1:3000
   ```

3. **抓取特定源地址的流量**
   ```bash
   sudo ./httpcap -i en0 -src 192.168.1.100
   ```

4. **抓取特定目标地址的流量**
   ```bash
   sudo ./httpcap -i en0 -dst 10.0.0.1
   ```

5. **过滤特定 URI**
   ```bash
   sudo ./httpcap -i en0 -uri /api/
   ```

6. **过滤多个目标地址（或关系）**
   ```bash
   sudo ./httpcap -i lo0 -dst 127.0.0.1:3000,127.0.0.1:8080
   ```

7. **组合过滤条件，限制抓包数量**
   ```bash
   sudo ./httpcap -i en0 -src 192.168.1 -uri /login -n 20
   ```

## 注意事项

- 需要 root 权限运行（使用 `sudo`）
- **本地回环流量**（127.0.0.1）需要使用 `lo0`（macOS）或 `lo`（Linux）接口
- 外部网络流量使用物理网络接口（如 `en0`、`eth0` 等）
- 仅支持 HTTP 协议，不支持 HTTPS
- 指定 `-src` 或 `-dst` 时会捕获所有 TCP 端口，否则仅捕获 80 端口
- 过滤条件支持部分匹配
- 达到最大抓包数量后自动停止
- 按 `Ctrl+C` 可随时停止抓包

## 输出格式

```
[序号] 源地址:端口 -> 目标地址:端口
HTTP 请求/响应头部信息
--------------------------------------------------------------------------------
```

## 故障排除

1. **权限错误**: 确保使用 `sudo` 运行
2. **接口不存在**: 使用 `-l` 参数查看可用接口
3. **编译错误**: 确保已安装 libpcap 开发库
