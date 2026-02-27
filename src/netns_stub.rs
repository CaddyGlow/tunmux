use crate::error::{AppError, Result};

pub fn create(_name: &str) -> Result<()> {
    Err(AppError::Namespace(
        "network namespaces are supported only on Linux".into(),
    ))
}

pub fn delete(_name: &str) -> Result<()> {
    Ok(())
}

#[allow(dead_code)]
pub fn exists(_name: &str) -> bool {
    false
}

pub fn exec(_namespace: &str, _args: &[&str]) -> Result<()> {
    Err(AppError::Namespace(
        "network namespace execution is supported only on Linux".into(),
    ))
}

pub fn remove_namespace_dir(_namespace: &str) -> Result<()> {
    Ok(())
}

#[allow(dead_code)]
pub fn enter(_name: &str) -> Result<()> {
    Err(AppError::Namespace(
        "network namespace operations are supported only on Linux".into(),
    ))
}
