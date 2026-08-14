use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    SeedExample(SeedExampleArgs),
    Show(ShowPolicyArgs),
}

#[derive(Debug, Args, Clone)]
pub struct SeedExampleArgs {}

#[derive(Debug, Args, Clone)]
pub struct ShowPolicyArgs {}
