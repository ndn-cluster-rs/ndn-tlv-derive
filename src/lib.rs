use quote::quote;
use syn::{Data, Fields};

#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(tlv))]
struct TlvAttr(usize);

#[proc_macro_derive(Tlv, attributes(tlv))]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let mut input = syn::parse2::<syn::DeriveInput>(input.into()).unwrap();

    let TlvAttr(typ) = deluxe::extract_attributes(&mut input).unwrap();

    let derivee = input.ident;

    let mut field_names = Vec::new();

    let fields = {
        let mut ret = Vec::new();
        match input.data {
            Data::Union(_) => panic!("Deriving Tlv on Unions is not supported"),
            Data::Struct(struct_data) => match struct_data.fields {
                Fields::Unit => {}
                Fields::Unnamed(_) => panic!("Cannot derive Tlv on struct with unnamed fields"),
                Fields::Named(fields) => {
                    field_names = Vec::with_capacity(fields.named.len());
                    ret = Vec::with_capacity(fields.named.len());
                    ret.extend(fields.named);
                }
            },
            Data::Enum(_) => unimplemented!(),
        }
        ret
    };

    let impls = {
        let mut initialisers = Vec::with_capacity(fields.len());
        for field in fields {
            let ty = &field.ty;
            let ident = field.ident.as_ref().unwrap();
            initialisers.push(quote! {
                #ident: <#ty as ::ndn_tlv::TlvDecode>::decode(&mut inner_data)?
            });
            field_names.push(ident.to_owned());
        }

        quote! {
            impl ::ndn_tlv::TlvDecode for #derivee {
                fn decode(bytes: &mut ::ndn_tlv::bytes::Bytes) -> ::ndn_tlv::Result<Self> {
                    use ::ndn_tlv::bytes::Buf;
                    let typ = ::ndn_tlv::VarNum::decode(bytes)?;
                    if typ.value() != Self::TYP {
                        return Err(::ndn_tlv::TlvError::TypeMismatch {
                            expected: Self::TYP,
                            found: typ.value(),
                        });
                    }
                    let length = ::ndn_tlv::VarNum::decode(bytes)?;
                    let mut inner_data = bytes.copy_to_bytes(length.value());

                    Ok(Self { #(#initialisers,)* })
                }
            }

            impl ::ndn_tlv::TlvEncode for #derivee {
                fn encode(&self) -> ::ndn_tlv::bytes::Bytes {
                    use ::ndn_tlv::bytes::BufMut;
                    let mut bytes = ::ndn_tlv::bytes::BytesMut::with_capacity(self.size());

                    bytes.put(::ndn_tlv::VarNum::new(Self::TYP).encode());
                    bytes.put(::ndn_tlv::VarNum::new(self.inner_size()).encode());
                    #(
                        bytes.put(self.#field_names.encode());
                        )*

                    bytes.freeze()
                }

                fn size(&self) -> usize {
                    ::ndn_tlv::VarNum::new(Self::TYP).size()
                        + ::ndn_tlv::VarNum::new(self.inner_size()).size()
                        #(+ self.#field_names.size())*
                }
            }
        }
    };

    quote! {
        impl ::ndn_tlv::Tlv for #derivee {
            const TYP: usize = #typ;

            fn inner_size(&self) -> usize {
                0 #(+ self.#field_names.size() )*
            }
        }

        #impls
    }
    .into()
}
