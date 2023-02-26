use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use proc_macro::TokenStream;
use proc_macro2::{Group, Span};
use quote::{quote, quote_spanned};

use proc_macro_error::{abort, proc_macro_error};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    parse, parse2, Attribute, Expr, ExprCast, Ident, Item, ItemEnum, ItemStruct, Lit, Meta, Path,
    Result, Token, Type, TypePath, Visibility,
};

use once_cell::sync::OnceCell;

struct GlobalState {
    declared_identifiers: Vec<String>,
}

static STATE: OnceCell<GlobalState> = OnceCell::new();

fn get_state() -> &'static GlobalState {
    STATE.get_or_init(|| {
        let sys_file = {
            // Load the header file and extract the constants defined inside.
            // This is what determines whether optional attributes (or enum variants)
            // will be supported or not in the resulting binary.
            let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("sys.rs");
            let mut sys_file = String::new();
            File::open(out_path)
                .expect("Error: could not open the output header file")
                .read_to_string(&mut sys_file)
                .expect("Could not read the header file");
            syn::parse_file(&sys_file).expect("Could not parse the header file")
        };

        let mut declared_identifiers = Vec::new();
        for item in sys_file.items {
            if let Item::Const(v) = item {
                declared_identifiers.push(v.ident.to_string());
            }
        }

        GlobalState {
            declared_identifiers,
        }
    })
}

struct Field<'a> {
    name: &'a Ident,
    ty: &'a Type,
    args: FieldArgs,
    netlink_type: Path,
    vis: &'a Visibility,
    attrs: Vec<&'a Attribute>,
}

#[derive(Default)]
struct FieldArgs {
    netlink_type: Option<Path>,
    override_function_name: Option<String>,
    optional: bool,
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
                    "optional" => {
                        if let Lit::Bool(boolean) = &namevalue.lit {
                            args.optional = boolean.value;
                        } else {
                            abort!(&namevalue.lit.span(), "Expected a boolean");
                        }
                    }
                    _ => abort!(arg.span(), "Unsupported macro parameter"),
                }
            }
            _ => abort!(arg.span(), "Unrecognized argument"),
        }
    }
    Ok(args)
}

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

fn parse_struct_args(input: TokenStream) -> Result<StructArgs> {
    let mut args = StructArgs::default();
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attribute_args = parser.parse(input.clone())?;
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
                _ => abort!(arg.span(), "Unsupported macro parameter"),
            }
        } else {
            abort!(arg.span(), "Unrecognized argument");
        }
    }
    Ok(args)
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn nfnetlink_struct(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(item).unwrap();
    let name = ast.ident;

    let args = match parse_struct_args(attrs) {
        Ok(x) => x,
        Err(_) => abort!(Span::call_site(), "Could not parse the macro arguments"),
    };

    let state = get_state();

    let mut fields = Vec::with_capacity(ast.fields.len());
    let mut identical_fields = Vec::new();

    'out: for field in ast.fields.iter() {
        for attr in field.attrs.iter() {
            if let Some(id) = attr.path.get_ident() {
                if id == "field" {
                    let field_args = match parse_field_args(attr.tokens.clone()) {
                        Ok(x) => x,
                        Err(_) => {
                            abort!(attr.tokens.span(), "Could not parse the field attributes")
                        }
                    };
                    if let Some(netlink_type) = field_args.netlink_type.clone() {
                        // optional fields are not generated when the kernel version you have on
                        // the system does not support that field
                        if field_args.optional {
                            let netlink_type_ident = netlink_type
                                .segments
                                .last()
                                .expect("empty path?")
                                .ident
                                .to_string();
                            if !state.declared_identifiers.contains(&netlink_type_ident) {
                                // reject the optional identifier
                                continue 'out;
                            }
                        }

                        fields.push(Field {
                            name: field.ident.as_ref().expect("Should be a names struct"),
                            ty: &field.ty,
                            args: field_args,
                            netlink_type,
                            vis: &field.vis,
                            // drop the "field" attribute
                            attrs: field
                                .attrs
                                .iter()
                                .filter(|x| x.path.get_ident() != attr.path.get_ident())
                                .collect(),
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

        let muttable_getter_name = format!("get_mut_{}", field_str);
        let muttable_getter_name = Ident::new(&muttable_getter_name, field.name.span());

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

            pub fn #muttable_getter_name(&mut self) -> Option<&mut #field_type> {
                self.#field_name.as_mut()
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
                        return Err(crate::error::DecodeError::InvalidDataSize);
                    }
                    self.#field_name = Some(val);
                    Ok(())
                }
            )
        });
        quote!(
            impl crate::nlmsg::AttributeDecoder for #name {
                #[allow(dead_code)]
                fn decode_attribute(&mut self, attr_type: u16, buf: &[u8]) -> Result<(), crate::error::DecodeError> {
                    use crate::nlmsg::NfNetlinkDeserializable;
                    debug!("Decoding attribute {} in type {}", attr_type, std::any::type_name::<#name>());
                    match attr_type {
                        #(#match_entries),*
                        _ => Err(crate::error::DecodeError::UnsupportedAttributeType(attr_type)),
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
                    size += crate::nlmsg::pad_netlink_object::<crate::sys::nlattr>()
                        + crate::nlmsg::pad_netlink_object_with_variable_size(val.get_size());
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
                        let size = crate::nlmsg::pad_netlink_object::<crate::sys::nlattr>()
                            + crate::nlmsg::pad_netlink_object_with_variable_size(val.get_size());
                        addr = &mut addr[size..];
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

                fn write_payload(&self, mut addr: &mut [u8]) {
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
        let vis = &field.vis;
        quote_spanned!(name.span() => #(#attrs) * #vis #name: Option<#ty>, )
    });
    let nfnetlinkdeserialize_impl = if args.derive_deserialize {
        quote!(
            impl crate::nlmsg::NfNetlinkDeserializable for #name {
                fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), crate::error::DecodeError> {
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

struct Variant<'a> {
    inner: &'a syn::Variant,
    name: &'a Ident,
    value: &'a Path,
}

#[derive(Default)]
struct EnumArgs {
    nested: bool,
    ty: Option<Path>,
}

fn parse_enum_args(input: TokenStream) -> Result<EnumArgs> {
    let mut args = EnumArgs::default();
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attribute_args = parser.parse(input)?;
    for arg in attribute_args.iter() {
        match arg {
            Meta::Path(path) => {
                if args.ty.is_none() {
                    args.ty = Some(path.clone());
                } else {
                    abort!(arg.span(), "A value can only have a single representation");
                }
            }
            Meta::NameValue(namevalue) => {
                let key = namevalue
                    .path
                    .get_ident()
                    .expect("the macro parameter is not an ident?")
                    .to_string();
                match key.as_str() {
                    "nested" => {
                        if let Lit::Bool(boolean) = &namevalue.lit {
                            args.nested = boolean.value;
                        } else {
                            abort!(&namevalue.lit.span(), "Expected a boolean");
                        }
                    }
                    _ => abort!(arg.span(), "Unsupported macro parameter"),
                }
            }
            _ => abort!(arg.span(), "Unrecognized argument"),
        }
    }
    Ok(args)
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn nfnetlink_enum(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemEnum = parse(item).unwrap();
    let name = ast.ident;

    let args = match parse_enum_args(attrs) {
        Ok(x) => x,
        Err(_) => abort!(Span::call_site(), "Could not parse the macro arguments"),
    };

    if args.ty.is_none() {
        abort!(
            Span::call_site(),
            "The target type representation is unspecified"
        );
    }

    let mut variants = Vec::with_capacity(ast.variants.len());

    for variant in ast.variants.iter() {
        if variant.discriminant.is_none() {
            abort!(variant.ident.span(), "Missing value");
        }
        let discriminant = variant.discriminant.as_ref().unwrap();
        if let syn::Expr::Path(path) = &discriminant.1 {
            variants.push(Variant {
                inner: variant,
                name: &variant.ident,
                value: &path.path,
            });
        } else {
            abort!(discriminant.1.span(), "Expected a path");
        }
    }

    let repr_type = args.ty.unwrap();
    let match_entries = variants.iter().map(|variant| {
        let variant_name = variant.name;
        let variant_value = &variant.value;
        quote!( x if x == (#variant_value as #repr_type) => Ok(Self::#variant_name), )
    });
    let unknown_type_ident = Ident::new(&format!("Unknown{}", name.to_string()), name.span());
    let tryfrom_impl = quote!(
        impl ::core::convert::TryFrom<#repr_type> for #name {
            type Error = crate::error::DecodeError;

            fn try_from(val: #repr_type) -> Result<Self, Self::Error> {
                    match val {
                        #(#match_entries) *
                        value => Err(crate::error::DecodeError::#unknown_type_ident(value))
                    }
            }
        }
    );
    let nfnetlinkdeserialize_impl = quote!(
        impl crate::nlmsg::NfNetlinkDeserializable for #name {
            fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), crate::error::DecodeError> {
                let (v, remaining_data) = #repr_type::deserialize(buf)?;
                <#name>::try_from(v).map(|x| (x, remaining_data))
            }
        }
    );
    let vis = &ast.vis;
    let attrs = ast.attrs;
    let original_variants = variants.into_iter().map(|x| {
        let mut inner = x.inner.clone();
        let mut discriminant = inner.discriminant.as_mut().unwrap();
        let cur_value = discriminant.1.clone();
        let cast_value = Expr::Cast(ExprCast {
            attrs: vec![],
            expr: Box::new(cur_value),
            as_token: Token![as](name.span()),
            ty: Box::new(Type::Path(TypePath {
                qself: None,
                path: repr_type.clone(),
            })),
        });
        discriminant.1 = cast_value;
        inner
    });
    let res = quote! {
        #[repr(#repr_type)]
        #(#attrs) * #vis enum #name {
            #(#original_variants),*
        }

        impl crate::nlmsg::NfNetlinkAttribute for #name {
            fn get_size(&self) -> usize {
                (*self as #repr_type).get_size()
            }

            fn write_payload(&self, addr: &mut [u8]) {
                (*self as #repr_type).write_payload(addr);
            }
        }

        #tryfrom_impl

        #nfnetlinkdeserialize_impl
    };

    res.into()
}
