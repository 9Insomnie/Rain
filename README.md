# Rain - 内存反映射加载器 (Reflective PE Loader)

`Rain` 是一个基于 Nim 语言编写的高性能、隐蔽的内存加载器。它能够将预先加密的 PE 文件（如 `fscan`）直接在内存中解密并加载运行，而无需将明文程序写入磁盘。

## 核心特性

* **全内存运行**：被加载的 Payload 全程不落地，通过 `Reflective Loader` 技术在内存中模拟 Windows 加载逻辑。
* **静态免杀**：Payload 以 XOR 加密形式静态存储在 Loader 数据段中，有效避开静态特征扫描。
* **PEB 参数劫持**：通过底层汇编直接修改进程环境块（PEB），支持动态传递命令行参数给内存中的 PE。
* **极致轻量**：使用 GCC 兼容的内联汇编和 `winim/lean` 库，最小化二进制文件体积。
* **高兼容性**：支持修复导入表（IAT）和重定位表（Relocation），确保复杂的 PE 文件能正常运行。

---

## 技术实现原理

1. **解密阶段**：从数据段读取 `staticRead` 导入的加密数据，通过 XOR 密钥进行内存解密。
2. **映射阶段**：调用 `VirtualAlloc` 分配内存，并根据 PE 头部的 `Section Headers` 将各个节（.text, .data, .rdata 等）映射到对应位置。
3. **修复阶段**：
* **IAT 修复**：遍历导入表，使用 `LoadLibrary` 和 `GetProcAddress` 填充真实的函数地址。
* **重定位修复**：计算内存地址增量（Delta），根据重定位表修正绝对地址引用。


4. **环境模拟**：通过 `gs:[0x60]` 偏移获取 PEB，直接劫持 `ProcessParameters` 中的命令行字符串。
5. **交付执行**：计算 `EntryPoint` 地址并跳转执行。

---

## 使用指南

### 1. 准备 Payload

首先，你需要一个经过 XOR 加密的 `fscan.exe`。你可以使用以下 Python 脚本生成：

```python
# encrypt.py
key = 0x42
with open("fscan.exe", "rb") as f:
    data = f.read()

enc_data = bytes([b ^ key for b in data])
with open("fscan.enc", "wb") as f:
    f.write(enc_data)

```

### 2. 环境要求

* Nim 编译器 (建议 2.0+)
* MinGW-w64 (GCC 编译器)
* `winim` 库：`nimble install winim`

### 3. 编译选项

使用以下命令进行极致瘦身编译：

```powershell
nim c -d:danger -d:strip --opt:size --threads:on --cpu:amd64 rain.nim

```

**参数说明：**

* `-d:danger`: 移除所有运行时检查，提高速度并减小体积。
* `-d:strip`: 剥离符号表和调试信息。
* `--opt:size`: 针对文件大小进行优化。

### 4. 运行

编译完成后，你可以像使用原程序一样直接传递参数：

```powershell
.\rain.exe -h 192.168.1.1 -o result.txt

```

---

## 免责声明

本工具仅限于**授权的安全审计**和**技术研究**使用。用户需遵守当地相关法律法规。由于非法使用本工具而导致的任何后果，由使用者自行承担，开发者不承担任何法律责任。
