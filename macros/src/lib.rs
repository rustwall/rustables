use proc_macro::TokenStream;
use proc_macro2::Group;
use quote::quote;

use proc_macro_error::{abort, proc_macro_error};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Struct;
use syn::{
    parse, parse2, parse_macro_input, Attribute, Expr, ExprLit, FnArg, Ident, ItemFn, ItemStruct,
    Lit, Meta, NestedMeta, Pat, PatIdent, Path, Result, ReturnType, Token, Type, TypePath,
};
use syn::{parse::Parse, PatReference};
use syn::{parse::ParseStream, TypeReference};

struct Field<'a> {
    name: &'a Ident,
    ty: &'a Type,
    args: FieldArgs,
    netlink_type: Path,
    attrs: Vec<&'a Attribute>,
}

#[derive(Debug, Default)]
struct FieldArgs {
    netlink_type: Option<Path>,
    override_function_name: Option<String>,
}

fn parse_field_args(input: proc_macro2::TokenStream) -> Result<FieldArgs> {
    let input = parse2::<Group>(input)?.stream();
    let mut args = FieldArgs::default();
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attribute_args = parser.parse2(input)?;
    for arg in attribute_args.iter() {
        match arg {
            Meta::Path(path) => {
                if args.netlink_type.is_none() {
                    args.netlink_type = Some(path.clone());
                } else {
                    abort!(
                        arg.span(),
                        "Only a single netlink value can exist for a given field"
                    );
                }
            }
            Meta::NameValue(namevalue) => {
                let key = namevalue
                    .path
                    .get_ident()
                    .expect("the macro parameter is not an ident?")
                    .to_string();
                match key.as_str() {
                    "name_in_functions" => {
                        if let Lit::Str(val) = &namevalue.lit {
                            args.override_function_name = Some(val.value());
                        } else {
                            abort!(&namevalue.lit.span(), "Expected a string literal");
                        }
                    }
                    _ => abort!(key.span(), "Unsupported macro parameter"),
                }
            }
            _ => abort!(arg.span(), "Unrecognized argument"),
        }
    }
    Ok(args)
}

#[derive(Debug)]
struct StructArgs {
    nested: bool,
    derive_decoder: bool,
    derive_deserialize: bool,
}

impl Default for StructArgs {
    fn default() -> Self {
        Self {
            nested: false,
            derive_decoder: true,
            derive_deserialize: true,
        }
    }
}

fn parse_struct_args(args: &mut StructArgs, input: TokenStream) -> Result<()> {
    if input.is_empty() {
        return Ok(());
    }
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attribute_args = parser.parse(input)?;
    for arg in attribute_args.iter() {
        if let Meta::NameValue(namevalue) = arg {
            let key = namevalue
                .path
                .get_ident()
                .expect("the macro parameter is not an ident?")
                .to_string();
            match key.as_str() {
                "derive_decoder" => {
                    if let Lit::Bool(boolean) = &namevalue.lit {
                        args.derive_decoder = boolean.value;
                    } else {
                        abort!(&namevalue.lit.span(), "Expected a boolean");
                    }
                }
                "nested" => {
                    if let Lit::Bool(boolean) = &namevalue.lit {
                        args.nested = boolean.value;
                    } else {
                        abort!(&namevalue.lit.span(), "Expected a boolean");
                    }
                }
                "derive_deserialize" => {
                    if let Lit::Bool(boolean) = &namevalue.lit {
                        args.derive_deserialize = boolean.value;
                    } else {
                        abort!(&namevalue.lit.span(), "Expected a boolean");
                    }
                }
                _ => abort!(key.span(), "Unsupported macro parameter"),
            }
        } else {
            abort!(arg.span(), "Unrecognized argument");
        }
    }
    Ok(())
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn nfnetlink_struct(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(item).unwrap();
    let name = ast.ident;

    let mut args = StructArgs::default();
    parse_struct_args(&mut args, attrs).expect("Could not parse the macro arguments");

    let mut fields = Vec::with_capacity(ast.fields.len());
    let mut identical_fields = Vec::new();

    'out: for field in ast.fields.iter() {
        for attr in field.attrs.iter() {
            if let Some(id) = attr.path.get_ident() {
                if id == "field" {
                    let field_args = parse_field_args(attr.tokens.clone())
                        .expect("Could not parse the field attributes");
                    if let Some(netlink_type) = field_args.netlink_type.clone() {
                        fields.push(Field {
                            name: field.ident.as_ref().expect("Should be a names struct"),
                            ty: &field.ty,
                            args: field_args,
                            netlink_type,
                            attrs: field.attrs.iter().filter(|x| *x != attr).collect(),
                        });
                    } else {
                        abort!(attr.tokens.span(), "Missing Netlink Type in field");
                    }
                    continue 'out;
                }
            }
        }
        identical_fields.push(field);
    }

    let getters_and_setters = fields.iter().map(|field| {
        let field_name = field.name;
        // use the name override if any
        let field_str = field_name.to_string();
        let field_str = field
            .args
            .override_function_name
            .as_ref()
            .map(|x| x.as_str())
            .unwrap_or(field_str.as_str());
        let field_type = field.ty;

        let getter_name = format!("get_{}", field_str);
        let getter_name = Ident::new(&getter_name, field.name.span());

        let setter_name = format!("set_{}", field_str);
        let setter_name = Ident::new(&setter_name, field.name.span());

        let in_place_edit_name = format!("with_{}", field_str);
        let in_place_edit_name = Ident::new(&in_place_edit_name, field.name.span());
        quote!(
            #[allow(dead_code)]
            impl #name {
            pub fn #getter_name(&self) -> Option<&#field_type> {
                self.#field_name.as_ref()
            }

            pub fn #setter_name(&mut self, val: impl Into<#field_type>) {
                self.#field_name = Some(val.into());
            }

            pub fn #in_place_edit_name(mut self, val: impl Into<#field_type>) -> Self {
                self.#field_name = Some(val.into());
                self
            }
        })
    });

    let decoder = if args.derive_decoder {
        let match_entries = fields.iter().map(|field| {
            let field_name = field.name;
            let field_type = field.ty;
            let netlink_value = &field.netlink_type;
            quote!(
                x if x == #netlink_value => {
                    debug!("Calling {}::deserialize()", std::any::type_name::<#field_type>());
                    let (val, remaining) = <#field_type>::deserialize(buf)?;
                    if remaining.len() != 0 {
                        return Err(crate::parser::DecodeError::InvalidDataSize);
                    }
                    self.#field_name = Some(val);
                    Ok(())
                }
            )
        });
        quote!(
            impl crate::nlmsg::AttributeDecoder for #name {
                #[allow(dead_code)]
                fn decode_attribute(&mut self, attr_type: u16, buf: &[u8]) -> Result<(), crate::parser::DecodeError> {
                    use crate::nlmsg::NfNetlinkDeserializable;
                    debug!("Decoding attribute {} in type {}", attr_type, std::any::type_name::<#name>());
                    match attr_type {
                        #(#match_entries),*
                        _ => Err(crate::parser::DecodeError::UnsupportedAttributeType(attr_type)),
                    }
                }
            }
        )
    } else {
        proc_macro2::TokenStream::new()
    };

    let nfnetlinkattribute_impl = {
        let size_entries = fields.iter().map(|field| {
            let field_name = field.name;
            quote!(
                if let Some(val) = &self.#field_name {
                    // Attribute header + attribute value
                    size += crate::parser::pad_netlink_object::<crate::sys::nlattr>()
                        + crate::parser::pad_netlink_object_with_variable_size(val.get_size());
                }
            )
        });
        let write_entries = fields.iter().map(|field| {
            let field_name = field.name;
            let field_str = field_name.to_string();
            let netlink_value = &field.netlink_type;
            quote!(
                if let Some(val) = &self.#field_name {
                    debug!("writing attribute {} - {:?}", #field_str, val);

                    crate::parser::write_attribute(#netlink_value, val, addr);

                    #[allow(unused)]
                    {
                        let size = crate::parser::pad_netlink_object::<crate::sys::nlattr>()
                            + crate::parser::pad_netlink_object_with_variable_size(val.get_size());
                        addr = addr.offset(size as isize);
                    }
                }
            )
        });
        let nested = args.nested;
        quote!(
            impl crate::nlmsg::NfNetlinkAttribute for #name {
                fn is_nested(&self) -> bool {
                    #nested
                }

                fn get_size(&self) -> usize {
                    use crate::nlmsg::NfNetlinkAttribute;

                    let mut size = 0;
                    #(#size_entries) *
                    size
                }

                unsafe fn write_payload(&self, mut addr: *mut u8) {
                    use crate::nlmsg::NfNetlinkAttribute;

                    #(#write_entries) *
                }
            }
        )
    };

    let vis = &ast.vis;
    let attrs = ast.attrs;
    let new_fields = fields.iter().map(|field| {
        let name = field.name;
        let ty = field.ty;
        let attrs = &field.attrs;
        quote!( #(#attrs) * #name: Option<#ty>, )
    });
    let nfnetlinkdeserialize_impl = if args.derive_deserialize {
        quote!(
            impl crate::nlmsg::NfNetlinkDeserializable for #name {
                fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), crate::parser::DecodeError> {
                    Ok((crate::parser::read_attributes(buf)?, &[]))
                }
            }
        )
    } else {
        proc_macro2::TokenStream::new()
    };
    let res = quote! {
        #(#attrs) * #vis struct #name {
            #(#new_fields)*
            #(#identical_fields),*
        }

        #(#getters_and_setters) *

        #decoder

        #nfnetlinkattribute_impl

        #nfnetlinkdeserialize_impl
    };

    res.into()
}
