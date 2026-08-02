# ndn-tlv-derive

[![docs.rs](https://img.shields.io/docsrs/ndn-tlv-derive)](https://docs.rs/ndn-tlv-derive)
[![crates.io](https://img.shields.io/crates/v/ndn-tlv-derive)](https://crates.io/crates/ndn-tlv-derive)
[![license](https://img.shields.io/crates/l/ndn-tlv-derive)](https://github.com/ndn-cluster-rs/ndn-tlv-derive/blob/master/LICENSE)

The `Tlv` derive macro used by [`ndn-tlv`](https://crates.io/crates/ndn-tlv) to implement its `TlvEncode`, `TlvDecode`, and `Tlv` traits for structs and enums.

This crate isn't meant to be used on its own -- `ndn-tlv` re-exports the macro as `ndn_tlv::Tlv`, so add `ndn-tlv` as a dependency instead.

## License

MIT

---

Produced as part of a Master's thesis in Computer Science.
