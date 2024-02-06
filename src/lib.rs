use quote::quote;
use syn::{Data, Fields};

#[derive(deluxe::ParseMetaItem)]
struct TlvAttrKW {
    #[deluxe(default)]
    internal: bool,
}

#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(tlv))]
struct TlvAttr(usize, #[deluxe(flatten)] TlvAttrKW);

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

    let mut field_names = Vec::new();
    let named;

    let fields = {
        let mut ret = Vec::new();
        match input.data {
            Data::Union(_) => panic!("Deriving Tlv on Unions is not supported"),
            Data::Struct(struct_data) => match struct_data.fields {
                Fields::Unit => named = true,
                Fields::Unnamed(fields) => {
                    field_names = Vec::with_capacity(fields.unnamed.len());
                    ret = Vec::with_capacity(fields.unnamed.len());
                    ret.extend(fields.unnamed);
                    named = false;
                }
                Fields::Named(fields) => {
                    field_names = Vec::with_capacity(fields.named.len());
                    ret = Vec::with_capacity(fields.named.len());
                    ret.extend(fields.named);
                    named = true;
                }
            },
            Data::Enum(_) => unimplemented!(),
        }
        ret
    };

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

        quote! {
            impl #crate_name::TlvDecode for #derivee {
                fn decode(bytes: &mut #crate_name::bytes::Bytes) -> #crate_name::Result<Self> {
                    use #crate_name::bytes::Buf;
                    #crate_name::find_tlv::<Self>(bytes)?;
                    let _ = #crate_name::VarNum::decode(bytes)?;
                    let length = #crate_name::VarNum::decode(bytes)?;
                    let mut inner_data = bytes.copy_to_bytes(length.value());

                    #initialiser
                }
            }

            impl #crate_name::TlvEncode for #derivee {
                fn encode(&self) -> #crate_name::bytes::Bytes {
                    use #crate_name::bytes::BufMut;
                    let mut bytes = #crate_name::bytes::BytesMut::with_capacity(self.size());

                    bytes.put(#crate_name::VarNum::new(Self::TYP).encode());
                    bytes.put(#crate_name::VarNum::new(self.inner_size()).encode());
                    #(
                        bytes.put(self.#field_names.encode());
                        )*

                    bytes.freeze()
                }

                fn size(&self) -> usize {
                    #crate_name::VarNum::new(Self::TYP).size()
                        + #crate_name::VarNum::new(self.inner_size()).size()
                        #(+ self.#field_names.size())*
                }
            }
        }
    };

    quote! {
        impl #crate_name::Tlv for #derivee {
            const TYP: usize = #typ;

            fn inner_size(&self) -> usize {
                0 #(+ self.#field_names.size() )*
            }
        }

        #impls
    }
    .into()
}
