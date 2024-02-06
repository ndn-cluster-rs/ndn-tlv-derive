use proc_macro2::Ident;
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

    let impls = match input.data {
        Data::Union(_) => panic!("Deriving Tlv on Unions is not supported"),
        Data::Struct(struct_data) => match struct_data.fields {
            Fields::Unit => panic!("Cannot derive Tlv on Unit struct"),
            Fields::Unnamed(_) => panic!("Cannot derive Tlv on struct with unnamed fields"),
            Fields::Named(fields) => {
                let mut decodes = Vec::with_capacity(fields.named.len() - 2);
                let mut initialisers = Vec::with_capacity(fields.named.len() - 2);
                let mut field_names = Vec::with_capacity(fields.named.len() - 2);
                let mut iter = fields.named.iter();

                if fields.named.len() < 2 {
                    panic!("A TLV record must have at least two fields: type and length");
                }

                let typ_name = iter.next().unwrap().ident.as_ref().unwrap();
                let length_name = iter.next().unwrap().ident.as_ref().unwrap();

                for field in iter {
                    let ty = &field.ty;
                    let ident = field.ident.as_ref().unwrap();
                    let name = Ident::new(&format!("field_{}", ident), ident.span());
                    decodes.push(quote! {
                        let #name = <#ty as ::ndn_tlv::TlvDecode>::decode(&mut inner_data)?;
                    });
                    initialisers.push(quote! {
                        #ident: #name
                    });
                    field_names.push(ident);
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
                            #(#decodes)*

                            Ok(Self { #typ_name: typ, #length_name: length, #(#initialisers,)* })
                        }
                    }

                    impl ::ndn_tlv::TlvEncode for #derivee {
                        fn encode(&self) -> ::ndn_tlv::bytes::Bytes {
                            use ::ndn_tlv::bytes::BufMut;
                            let mut bytes = ::ndn_tlv::bytes::BytesMut::with_capacity(self.size());

                            bytes.put(self.#typ_name.encode());
                            bytes.put(self.#length_name.encode());
                            #(
                                bytes.put(self.#field_names.encode());
                                )*

                            bytes.freeze()
                        }

                        fn size(&self) -> usize {
                            self.typ.size()
                                + self.length.size()
                                #(+ self.#field_names.size())*
                        }
                    }
                }
            }
        },
        Data::Enum(_) => unimplemented!(),
    };

    quote! {
        impl ::ndn_tlv::Tlv for #derivee {
            const TYP: usize = #typ;
        }

        #impls
    }
    .into()
}
