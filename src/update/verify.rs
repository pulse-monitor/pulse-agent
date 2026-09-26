//! 签名与摘要校验。**纯函数，可完整测到底。**
//!
//! 对应 [] 里的第 2、3 道防线：
//! minisign 验签 + SHA-256 清单校验（清单本身在签名覆盖范围内）。

use sha2::{Digest, Sha256};

/// 校验失败的原因。**每一种都必须导致放弃更新**，没有任何一种是可以「继续」的。
#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    /// 编译期没内置公钥 —— 自更新功能整个关闭
    NoPubkey,
    /// 内置的公钥本身格式不对（构建配置错了）
    BadPubkey,
    /// 签名文件格式不对
    BadSignature,
    /// 签名与清单内容不匹配 —— **这是被投毒时最可能看到的**
    SignatureMismatch,
    /// 清单里没有本平台这一行
    NotInManifest,
    /// 下载到的二进制摘要与清单不符
    DigestMismatch,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Reject::NoPubkey => "未内置更新公钥，自更新已关闭",
            Reject::BadPubkey => "内置的更新公钥格式不对（构建配置有误）",
            Reject::BadSignature => "签名文件格式不对",
            Reject::SignatureMismatch => "签名校验不通过 —— 更新包可能被篡改",
            Reject::NotInManifest => "清单里没有本平台对应的条目",
            Reject::DigestMismatch => "二进制摘要与清单不符 —— 更新包可能被篡改",
        };
        f.write_str(s)
    }
}

/// 用内置公钥验证清单的 minisign 签名。
///
/// `pubkey` 是 minisign 的公钥文本（`minisign -G` 产出的那两行，或只有 base64 那一行）。
/// **空公钥一律拒绝**，不做「没配就跳过校验」的处理 —— 那等于把第 2 道防线关掉。
pub fn verify_manifest(pubkey: &str, manifest: &[u8], signature: &str) -> Result<(), Reject> {
    let pubkey = pubkey.trim();
    if pubkey.is_empty() {
        return Err(Reject::NoPubkey);
    }
    let pk = minisign_verify::PublicKey::decode(pubkey)
        .or_else(|_| minisign_verify::PublicKey::from_base64(pubkey))
        .map_err(|_| Reject::BadPubkey)?;
    let sig = minisign_verify::Signature::decode(signature).map_err(|_| Reject::BadSignature)?;
    // 第三个参数是 allow_legacy：不允许 —— 旧格式用的是 pure Ed25519，
    // 没有把「被签的是什么文件」绑进去
    pk.verify(manifest, &sig, false)
        .map_err(|_| Reject::SignatureMismatch)
}

/// 校验下载到的二进制：摘要必须与（已验签的）清单里的那一行一致。
pub fn verify_binary(manifest: &str, filename: &str, bytes: &[u8]) -> Result<(), Reject> {
    let want = super::manifest::sha256_of(manifest, filename).ok_or(Reject::NotInManifest)?;
    let got: [u8; 32] = Sha256::digest(bytes).into();
    // 摘要比较用常量时间没有意义（两边都是公开值），但**必须是全等比较**
    if got != want {
        return Err(Reject::DigestMismatch);
    }
    Ok(())
}

/// 从 minisign 签名文本里提取 keynum（签名块 base64 解码后的第 3–10 字节，hex）。
///
/// minisign-verify 在验签时已经校验了「签名里的 keynum == 公钥里的 keynum」
/// （对不上就是 `SignatureMismatch`），这里只是把它解出来 —— 调用方在验签
/// 通过后记进日志。将来做密钥轮换时不用改验签逻辑，凭日志就能看出
/// 是哪把钥匙签的包：这是为轮换留的协议位（S1）。
///
/// 手写最小 base64 解码：签名块固定 74 字节，为它引一个 base64 库不值得；
/// 解码只用于日志展示，失败返回 `None`，不影响验签结果。
pub fn signature_keynum(signature: &str) -> Option<String> {
    let b64 = signature.lines().nth(1)?.trim();
    let raw = decode_base64(b64)?;
    if raw.len() != 74 {
        return None;
    }
    Some(
        raw[2..10]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
}

/// 最小 base64 解码（标准字母表）。只处理单行、无空白的输入。
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.as_bytes();
    if s.is_empty() || s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                if i < 2 || pad > 2 {
                    return None; // padding 只能出现在末尾 1–2 个
                }
                pad += 1;
            } else {
                if pad > 0 {
                    return None; // padding 后面不能再有数据
                }
                n = (n << 6) | u32::from(val(c)?);
            }
        }
        n <<= 6 * pad;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// 发布产物里本平台那一行的文件名。构建期由 `build.rs` 注入目标三元组。
pub fn asset_name() -> String {
    let target = env!("PULSE_TARGET");
    if target.contains("windows") {
        format!("pulse-agent-{target}.exe")
    } else {
        format!("pulse-agent-{target}")
    }
}

/// 编译期内置的公钥。空 = 自更新关闭。
pub fn builtin_pubkey() -> &'static str {
    env!("PULSE_UPDATE_PUBKEY")
}

#[cfg(test)]
mod tests {
    use super::*;

    // 用 minisign 真实生成的一组测试数据（私钥只用于生成这些常量，未入库）。
    // 见 tools/gen-test-keys.sh
    const PUBKEY: &str = include_str!("testdata/test.pub");
    const MANIFEST: &[u8] = include_bytes!("testdata/SHA256SUMS");
    const SIG: &str = include_str!("testdata/SHA256SUMS.minisig");

    #[test]
    fn accepts_a_genuine_signature() {
        assert_eq!(verify_manifest(PUBKEY, MANIFEST, SIG), Ok(()));
    }

    /// **R18 第 7 条的核心**：签名不对必须拒绝。
    #[test]
    fn rejects_tampered_manifest() {
        let mut bad = MANIFEST.to_vec();
        bad[0] ^= 1; // 改一个比特
        assert_eq!(
            verify_manifest(PUBKEY, &bad, SIG),
            Err(Reject::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_signature_from_another_key() {
        // 换一把公钥去验同一个签名 —— 攻击者拿自己的私钥签了个假清单的情形
        let other = include_str!("testdata/other.pub");
        assert_eq!(
            verify_manifest(other, MANIFEST, SIG),
            Err(Reject::SignatureMismatch)
        );
    }

    #[test]
    fn empty_pubkey_disables_updates_rather_than_skipping_checks() {
        // 绝不能是「没配公钥就不校验」
        assert_eq!(verify_manifest("", MANIFEST, SIG), Err(Reject::NoPubkey));
        assert_eq!(verify_manifest("   ", MANIFEST, SIG), Err(Reject::NoPubkey));
    }

    #[test]
    fn malformed_inputs_are_rejected_not_panicked() {
        assert_eq!(
            verify_manifest("not a key", MANIFEST, SIG),
            Err(Reject::BadPubkey)
        );
        assert_eq!(
            verify_manifest(PUBKEY, MANIFEST, "not a signature"),
            Err(Reject::BadSignature)
        );
        assert_eq!(
            verify_manifest(PUBKEY, MANIFEST, ""),
            Err(Reject::BadSignature)
        );
    }

    #[test]
    fn binary_digest_must_match_the_manifest() {
        // 清单里第一行对应 "hello\n" 的 sha256
        let m =
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  pulse-agent-test\n";
        assert_eq!(verify_binary(m, "pulse-agent-test", b"hello\n"), Ok(()));
        assert_eq!(
            verify_binary(m, "pulse-agent-test", b"hello!\n"),
            Err(Reject::DigestMismatch)
        );
        assert_eq!(
            verify_binary(m, "pulse-agent-other", b"hello\n"),
            Err(Reject::NotInManifest)
        );
    }

    #[test]
    fn asset_name_matches_the_build_target() {
        let n = asset_name();
        assert!(n.starts_with("pulse-agent-"));
        assert!(n.contains(env!("PULSE_TARGET")));
    }

    #[test]
    fn keynum_is_extracted_from_a_genuine_signature() {
        // keynum 必须和公钥里的 key ID 一致 —— minisign 公钥的 base64 解出来是
        // "Ed" + keyid[8] + pubkey[32]，取第 3–10 字节对比
        let keynum = signature_keynum(SIG).expect("应当解出 keynum");
        assert_eq!(keynum.len(), 16, "8 字节 hex");

        let pub_b64 = PUBKEY.lines().nth(1).expect("公钥要有 base64 那一行");
        let pub_raw = decode_base64(pub_b64.trim()).expect("公钥 base64 应当合法");
        assert_eq!(pub_raw.len(), 42, "Ed(2) + keyid(8) + pubkey(32)");
        let from_pub: String = pub_raw[2..10].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(keynum, from_pub, "签名里的 keynum 必须和公钥的 key ID 一致");
    }

    #[test]
    fn keynum_extraction_rejects_garbage() {
        assert!(signature_keynum("").is_none());
        assert!(signature_keynum("只有一行").is_none());
        assert!(signature_keynum("untrusted comment: x\n不是base64!!\n").is_none());
        // 长度不对的签名块
        assert!(signature_keynum("untrusted comment: x\nQUJD\n").is_none());
    }

    #[test]
    fn base64_decoder_handles_padding() {
        // "hello\n"：无 padding、1 个 padding、2 个 padding 各一种
        assert_eq!(decode_base64("aGVsbG8K"), Some(b"hello\n".to_vec()));
        assert_eq!(decode_base64("YWI="), Some(b"ab".to_vec()));
        assert_eq!(decode_base64("YQ=="), Some(b"a".to_vec()));
        // 非法输入
        assert!(decode_base64("abc").is_none(), "长度必须对齐到 4");
        assert!(decode_base64("====").is_none());
        assert!(decode_base64("AB=C").is_none(), "padding 后不能有数据");
        assert!(decode_base64("A**=").is_none(), "非法字符");
    }
}
