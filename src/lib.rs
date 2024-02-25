use quote::quote;
use syn::{Data, Field, Fields, GenericParam};

#[derive(deluxe::ParseMetaItem)]
struct TlvAttrKW {
    #[deluxe(default)]
    internal: bool,
}

#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(tlv))]
struct TlvAttr(#[deluxe(default)] usize, #[deluxe(flatten)] TlvAttrKW);

#[derive(deluxe::ExtractAttributes)]
struct TlvFieldAttr {
    #[deluxe(default)]
    default: bool,
}

fn derive_struct(
    fields: Vec<Field>,
    crate_name: proc_macro2::TokenStream,
    named: bool,
    derivee: proc_macro2::Ident,
    generics: syn::Generics,
    typ: usize,
) -> proc_macro::TokenStream {
    let (generic_args, decode_where, encode_where, tlv_where) = {
        let params: Vec<_> = generics
            .params
            .iter()
            .filter(|x| matches!(x, GenericParam::Type(_)))
            .collect();
        if params.len() > 0 {
            (
                quote! {
                    <#( #params ),*>
                },
                quote! {
                    where #(#params: #crate_name::TlvEncode, #params: #crate_name::TlvDecode),*
                },
                quote! {
                    where #(#params: #crate_name::TlvEncode),*
                },
                quote! {
                    where #(#params: #crate_name::TlvEncode),*
                },
            )
        } else {
            (quote! {}, quote! {}, quote! {}, quote! {})
        }
    };

    let mut field_names = Vec::with_capacity(fields.len());

    let impls = {
        let mut initialisers = Vec::with_capacity(fields.len());
        for (i, field) in fields.iter().enumerate() {
            let ty = &field.ty;
            if let Some(ref ident) = field.ident {
                initialisers.push(quote! {
                    #ident: <#ty as #crate_name::TlvDecode>::decode(&mut inner_data)?
                });
                field_names.push(quote!(#ident));
            } else {
                initialisers.push(quote! {
                    <#ty as #crate_name::TlvDecode>::decode(&mut inner_data)?
                });
                let idx = syn::Index::from(i);
                field_names.push(quote!(#idx));
            }
        }

        let initialiser = if named {
            quote! {Ok(Self { #(#initialisers,)* })}
        } else {
            quote! {
                Ok(Self (#(#initialisers,)*))
            }
        };

        let decode_impl = if typ == 0 {
            quote! {
                impl #generic_args #crate_name::TlvDecode for #derivee #generic_args #decode_where {
                    fn decode(bytes: &mut #crate_name::bytes::Bytes) -> #crate_name::Result<Self> {
                        let mut inner_data = bytes;
                        #initialiser
                    }
                }
            }
        } else {
            quote! {
                impl #generic_args #crate_name::TlvDecode for #derivee #generic_args #decode_where {
                    fn decode(bytes: &mut #crate_name::bytes::Bytes) -> #crate_name::Result<Self> {
                        use #crate_name::bytes::Buf;
                        #crate_name::find_tlv::<Self>(bytes, true)?;
                        let _ = #crate_name::VarNum::decode(bytes)?;
                        let length = #crate_name::VarNum::decode(bytes)?;
                        if bytes.remaining() < length.into() {
                            return Err(#crate_name::TlvError::UnexpectedEndOfStream);
                        }
                        let mut inner_data = bytes.copy_to_bytes(length.into());

                        #initialiser
                    }
                }
            }
        };

        let encode_impl = {
            let encode_header = if typ == 0 {
                quote! {}
            } else {
                quote! {
                    bytes.put(#crate_name::VarNum::from(Self::TYP).encode());
                    bytes.put(#crate_name::VarNum::from(self.inner_size()).encode());
                }
            };

            let size_header = if typ == 0 {
                quote! {0}
            } else {
                quote! {
                    #crate_name::VarNum::from(Self::TYP).size()
                        + #crate_name::VarNum::from(self.inner_size()).size()
                }
            };
            quote! {
                impl #generic_args #crate_name::TlvEncode for #derivee #generic_args #encode_where {
                    fn encode(&self) -> #crate_name::bytes::Bytes {
                        use #crate_name::bytes::BufMut;
                        let mut bytes = #crate_name::bytes::BytesMut::with_capacity(self.size());

                        #encode_header
                        #(
                            bytes.put(self.#field_names.encode());
                            )*

                        bytes.freeze()
                    }

                    fn size(&self) -> usize {
                        #size_header
                            #(+ self.#field_names.size())*
                    }
                }
            }
        };

        quote! {
            #decode_impl
            #encode_impl
        }
    };

    let tlv_impl = if typ != 0 {
        quote! {
            impl #generic_args #crate_name::Tlv for #derivee #generic_args #tlv_where {
                const TYP: usize = #typ;

                fn inner_size(&self) -> usize {
                    0 #(+ self.#field_names.size() )*
                }
            }
        }
    } else {
        quote! {}
    };

    quote! {
        #tlv_impl

        #impls
    }
    .into()
}

#[proc_macro_derive(Tlv, attributes(tlv))]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let mut input = syn::parse2::<syn::DeriveInput>(input.into()).unwrap();

    let TlvAttr(typ, kw) = deluxe::extract_attributes(&mut input).unwrap();

    let derivee = input.ident;
    let crate_name = if kw.internal {
        quote! {crate}
    } else {
        quote! {::ndn_tlv}
    };

    match input.data {
        Data::Union(_) => panic!("Deriving Tlv on Unions is not supported"),
        Data::Struct(struct_data) => match struct_data.fields {
            Fields::Unit => {
                derive_struct(Vec::new(), crate_name, true, derivee, input.generics, typ)
            }
            Fields::Unnamed(unnamed_fields) => {
                let mut fields = Vec::with_capacity(unnamed_fields.unnamed.len());
                fields.extend(unnamed_fields.unnamed);
                derive_struct(fields, crate_name, false, derivee, input.generics, typ)
            }
            Fields::Named(named_fields) => {
                let mut fields = Vec::with_capacity(named_fields.named.len());
                fields.extend(named_fields.named);
                derive_struct(fields, crate_name, true, derivee, input.generics, typ)
            }
        },
        Data::Enum(enm) => {
            let mut variants = Vec::with_capacity(enm.variants.len());
            let mut fields = Vec::with_capacity(enm.variants.len());
            let mut default_variant = None;

            for mut variant in enm.variants {
                let attrs: TlvFieldAttr = deluxe::extract_attributes(&mut variant).unwrap();
                if attrs.default {
                    assert!(default_variant.is_none());
                    default_variant = Some(variant.ident);
                } else {
                    variants.push(variant.ident);
                }

                if variant.fields.len() != 1 || !matches!(variant.fields, syn::Fields::Unnamed(_)) {
                    panic!("Enum variants must have exactly 1 unnamed field");
                }

                if !attrs.default {
                    fields.push(variant.fields.iter().next().unwrap().ty.clone());
                }
            }

            let decode_default = {
                if let Some(ref variant) = default_variant {
                    quote! {
                        _ => Ok(Self::#variant(#variant::decode(bytes)?)),
                    }
                } else {
                    quote! {
                        _ => Err(#crate_name::TlvError::TypeMismatch {
                            expected: 0, // TODO
                            found: typ.into(),
                        }),
                    }
                }
            };

            let encode_default_encode = {
                if let Some(ref variant) = default_variant {
                    quote! {
                        Self::#variant(x) => x.encode(),
                    }
                } else {
                    quote! {}
                }
            };

            let encode_default_size = {
                if let Some(ref variant) = default_variant {
                    quote! {
                        Self::#variant(x) => x.size(),
                    }
                } else {
                    quote! {}
                }
            };

            quote! {
                impl #crate_name::TlvDecode for #derivee {
                    fn decode(bytes: &mut #crate_name::bytes::Bytes) -> #crate_name::Result<Self> {
                        let mut cur = bytes.clone();

                        let typ = #crate_name::VarNum::decode(&mut cur)?;
                        match typ.into() {
                            #(
                            <#fields>::TYP => Ok(Self::#variants(
                                <#fields>::decode(bytes)?,
                            )),
                            )*
                            #decode_default
                        }
                    }
                }

                impl #crate_name::TlvEncode for #derivee {
                    fn encode(&self) -> #crate_name::bytes::Bytes {
                        match self {
                            #(
                            Self::#variants(x) => x.encode(),
                            #encode_default_encode
                            )*
                        }
                    }

                    fn size(&self) -> usize {
                        match self {
                            #(
                                Self::#variants(x) => x.size(),
                                #encode_default_size
                            )*
                        }
                    }
                }
            }
            .into()
        }
    }
}
