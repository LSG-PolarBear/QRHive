```text
╔═══════════════════════════════════════════════════════════════════════════
║
║   ██████  ██████  ██   ██ ██ ██    ██ ███████
║  ██    ██ ██   ██ ██   ██ ██ ██    ██ ██
║  ██    ██ ██████  ███████ ██ ██    ██ █████
║  ██ ▄▄ ██ ██   ██ ██   ██ ██  ██  ██  ██
║   ██████  ██   ██ ██   ██ ██   ████   ███████
║      ▀▀
║
║  QRHive Deep QR Code Analysis & Threat Hunting Tool Manual
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ I. Software Introduction ]
╠═══════════════════════════════════════════════════════════════════════════
║ QRHive is a localized tool designed for Blue Team analysis and Red Team
║ testing. It not only has powerful barcode decoding capabilities, but
║ also digs out malicious encodings, embedded images, dangerous features,
║ and threat intelligence (IoC) hidden behind QR codes.
║
║ [ Core Features ]
║ ├─► Multi-engine Fallback: zxing-cpp, pyzbar, opencv integrated.
║ ├─► Deep Unwrapping: Auto-decodes nested encodings (Base64, Hex, gzip)
║ │   up to 5 layers.
║ ├─► IoC Extraction: One-click extraction of IPs, domains, URLs, hashes,
║ │   CVEs, and registry paths.
║ ├─► Heuristic Scoring: Auto-highlights malicious features like
║ │   PowerShell obfuscation or pseudo-protocols.
║ ├─► Precise Visualization: Blue bounding box drawn at low level, always
║ │   sticks to the QR code regardless of window resizing.
║ └─► Global Dark Mode: Perfectly adapted UI darkening to protect eyes.
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ II. Functional Usage Guide ]
╠═══════════════════════════════════════════════════════════════════════════
║ [ 1. Analyze (Main Interface) ] ———— Deep Analysis for Single File
║ │
║ ├─► Step 1: Load Data
║ │    ├── Drag & drop the image into the left source area
║ │    ├── Shortcut Ctrl+O to select a file (PDF supported)
║ │    └── Shortcut Ctrl+V to paste clipboard screenshot
║ │
║ ├─► Step 2: View Results
║ │    └── Switch between 8 tabs on the right panel:
║ │         [Text] ── Decoded plaintext
║ │         [Image] ── Extracted images from QR
║ │         [Raw Bytes] ── Underlying data in Hex format
║ │         [Decoding Chain] ── Multi-layer decoding process
║ │         [Structured] ── WiFi password, URL params parsing
║ │         [IoC] ── Extracted domains/IPs/hashes etc.
║ │         [Suspicion] ── Threat score and hit rules
║ │         [EXIF] ── Image metadata
║ │
║ └─► Step 3: Export & Save
║      ├── Click [Copy All]: Copy text & IoC in one click
║      └── Click [Export Report]: Generate a well-formatted HTML report
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 2. Batch Processing ] ———— Rapid Multi-file Screening
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► Step 1: Add Samples
║ │    └── Go to [Batch] tab, add files or a whole folder
║ │
║ ├─► Step 2: Start Scan
║ │    └── Auto-iterates images, displays results in a table
║ │        (Engine/Suspicion/Time)
║ │
║ └─► Step 3: Export Data
║      └── Click [Export CSV] to save as a table for archiving
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 3. Generator ] ———— Create Test Samples
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► Step 1: Configure Parameters
║ │    └── Enter content, select EC level, border, colors
║ │        (ColorPicker supported)
║ │
║ └─► Step 2: Generate & Save
║      └── Click [Generate] to preview, then [Save PNG] to save locally
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 4. Range ] ———— Engine Capability Comparison
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► Step 1: Select Directory
║ │    └── Select a folder containing test images
║ │
║ └─► Step 2: Start Evaluation
║      └── Tests zxing / pyzbar / opencv, table shows ✓ or ✗ for each
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 5. Settings ] ———— Software Tuning
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► Preprocessing Strategies
║ │    └── For blurry images, check Grayscale/Binarize/Sharpen, auto-applied
║ │
║ ├─► Theme Switching
║ │    └── Select "Dark Mode" in dropdown, click [Apply Theme] globally
║ │
║ └─► Threat Rule Management
║      └── Open the rule file, modify rules/heuristics.json, then hot-reload
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 6. History & Camera ]
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► History Records
║ │    └── Go to [History] tab, view auto-saved evidence packages on exit
║ │
║ └─► Camera Scan
║      └── Click [Camera], aim at screen or paper QR, auto-analyze
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 7. Command Line Interface (CLI) ] ———— Automation Integration
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► Plain Text Output
║ │    └── python QRHive.py --scan sample.jpg
║ │
║ └─► JSON Intelligence Output
║      └── python QRHive.py --scan sample.jpg --json
╚═══════════════════════════════════════════════════════════════════════════
```

```text
╔═══════════════════════════════════════════════════════════════════════════
║
║   ██████  ██████  ██   ██ ██ ██    ██ ███████
║  ██    ██ ██   ██ ██   ██ ██ ██    ██ ██
║  ██    ██ ██████  ███████ ██ ██    ██ █████
║  ██ ▄▄ ██ ██   ██ ██   ██ ██  ██  ██  ██
║   ██████  ██   ██ ██   ██ ██   ████   ███████
║      ▀▀
║
║  QRHive 二维码深度解析与威胁分析工具使用手册
║
╠═══════════════════════════════════════════════════════════════════════════
║ 【一、 软件介绍】
╠═══════════════════════════════════════════════════════════════════════════
║ QRHive 是一款专为安全蓝队研判与红队测试设计的本地化工具。它不仅具备超强解码能力，
║ 更能将隐藏在二维码背后的恶意编码、内嵌图片、危险特征以及威胁情报全部挖掘出来。
║
║ [ 核心亮点 ]
║ ├─► 多引擎兜底：集成 zxing-cpp、pyzbar、opencv，识别率极高。
║ ├─► 深度剥洋葱：自动解包 Base64、Hex、gzip 等 5 层以内的嵌套编码。
║ ├─► 威胁情报提取：一键抓取 IP、域名、URL、Hash、CVE、注册表等 IoC。
║ ├─► 启发式打分：内置规则库，自动标红 PowerShell 混淆、伪协议等危险特征。
║ ├─► 精准可视化：底层重绘的蓝色定位框，无论怎么拖拽缩放绝不跑偏。
║ └─► 全局深色模式：完美适配的 UI 级黑化，保护视力。
║
╠═══════════════════════════════════════════════════════════════════════════
║ 【二、 各功能使用方法】
╠═══════════════════════════════════════════════════════════════════════════
║ [ 1. 解析 (主界面) ] ———— 单文件深度分析
║ │
║ ├─► 步骤一：载入数据
║ │    ├── 拖拽图片至左侧源图区
║ │    ├── 快捷键 Ctrl+O 选择文件（支持 PDF）
║ │    └── 快捷键 Ctrl+V 粘贴剪贴板截图
║ │
║ ├─► 步骤二：查看结果
║ │    └── 在右侧切换 8 大标签页：
║ │         [文本] ── 解码出的明文
║ │         [图片] ── 从二维码里抠出来的图
║ │         [原始字节] ── Hex 格式的底层数据
║ │         [解码链] ── 多层编码拆解过程
║ │         [结构化] ── WiFi密码、URL参数解析
║ │         [IoC] ── 提取的域名/IP/哈希等情报
║ │         [可疑度] ── 威胁评分及命中规则
║ │         [EXIF] ── 图片元数据
║ │
║ └─► 步骤三：导出与保存
║      ├── 点击【复制全部】：一键复制文本与 IoC
║      └── 点击【导出报告】：生成排版精美的 HTML 报告
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 2. 批量处理 ] ———— 多文件极速筛查
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► 步骤一：添加样本
║ │    └── 切换至【批量】页，点击添加文件或整个文件夹
║ │
║ ├─► 步骤二：开始扫描
║ │    └── 自动调用引擎遍历图片，表格展示结果（引擎/可疑度/耗时）
║ │
║ └─► 步骤三：导出数据
║      └── 点击【导出 CSV】，保存为表格供后续归档
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 3. 生成器 ] ———— 制作测试样本
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► 步骤一：配置参数
║ │    └── 输入框填入内容，选择纠错等级、边距、颜色（支持调色板）
║ │
║ └─► 步骤二：生成保存
║      └── 点击【生成】预览，满意后点击【保存 PNG】落盘
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 4. 靶场 ] ———— 引擎能力对比
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► 步骤一：选择目录
║ │    └── 点击选择包含一堆测试图的文件夹
║ │
║ └─► 步骤二：开始评估
║      └── 测试 zxing / pyzbar / opencv 三引擎，表格显示每个引擎的 ✓ 或 ✗
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 5. 设置 ] ———— 软件调优
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► 预处理策略
║ │    └── 遇到模糊图，勾选灰度/二值化/锐化，解析时自动应用
║ │
║ ├─► 主题切换
║ │    └── 下拉框选择“深色模式”，点击【应用主题】全局生效
║ │
║ └─► 威胁规则管理
║      └── 点击打开规则文件，修改 rules/heuristics.json 后热重载
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 6. 历史 & 摄像头 ]
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► 历史记录
║ │    └── 切换至【历史】页，查看历次退出时自动保存的证据包
║ │
║ └─► 摄像头扫描
║      └── 点击工具栏【摄像头】，对准屏幕或纸质二维码，识别后自动解析
║
╠═══════════════════════════════════════════════════════════════════════════
║ [ 7. 命令行模式 (CLI) ] ———— 自动化集成
╠═══════════════════════════════════════════════════════════════════════════
║ ├─► 普通文本输出
║ │    └── python QRHive.py --scan 样本.jpg
║ │
║ └─► JSON 情报输出
║      └── python QRHive.py --scan 样本.jpg --json
╚═══════════════════════════════════════════════════════════════════════════
```
