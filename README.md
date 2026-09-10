# StackChan Update Core

从个人 StackChan 扩展项目中精选的两个 Python 后端模块：发布清单签名验证，以及固件/资源包的上传校验和限时下载票据。

这是模块级代码样本，不是完整机器人系统或官方 StackChan 固件。仓库不包含前端、真实固件、个人配置、对话数据或生产密钥。

## 为什么选这两部分

- `stackchan_ai/release_manifest.py`：Ed25519 签名与验签、严格 JSON/schema 校验、版本兼容范围、HTTPS URL 与路径检查。体现发布数据的信任边界。
- `stackchan_ai/firmware_ota.py`：固件头及大小校验、资源表与长度检查、SHA-256 内容标识、线程锁和有时效的下载票据。体现二进制输入校验与生命周期管理。
- `tests/`：正常路径与篡改、过期、错误版本、越界输入等回归场景。测试密钥在运行时生成，测试固件由字节数组合成。

## 运行测试

Python 3.11 或 3.12，无需机器人硬件：

```bash
python -m pip install -e ".[test]"
python -m pytest -q
```

## 最小示例

下面创建的是校验用合成字节，不是可刷入设备的固件：

```python
from stackchan_ai.firmware_ota import FirmwareArtifactStore, MIN_FIRMWARE_SIZE

image = bytearray(MIN_FIRMWARE_SIZE)
image[0] = 0xE9
image[0x30:0x35] = b"1.0.0"
store = FirmwareArtifactStore()
artifact = store.stage("demo.bin", bytes(image))
print(artifact.public_summary())
ticket = store.issue_ticket(artifact.id)
assert store.resolve_ticket(artifact.id, ticket) is artifact
```

签名与公钥配置的完整调用方式见 `tests/test_release_manifest.py`。公钥配置必须来自应用信任的本地路径，不能从待验证的更新包中直接信任公钥。

## 验证边界

单元测试不代表真机 OTA 验收，也不是完整安全审计。固件头与长度检查不能证明固件可启动；SHA-256 本身不证明发布者身份。清单验签和文件仓库是独立模块，集成方仍需核对文件的 size/SHA-256 与已验签清单、实施请求鉴权、容量限制及设备写入后的恢复策略。

文件仓库驻留内存，进程结束后丢失，当前没有总容量淘汰策略。票据在到期前可重复使用。硬件槽位常量来自原项目，接入其他设备时必须核实分区布局。

本仓库仅提取上述后端模块及其测试，没有复制上游厂商固件或前端资源；不代表官方维护或背书。
