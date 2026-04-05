/// Metadata describing a single column in a query result set.
#[derive(Debug, Clone)]
pub struct ColumnInfo {
    pub name: String,
    pub type_name: String,
    pub nullable: bool,
    pub precision: Option<u16>,
    pub scale: Option<u16>,
}

impl ColumnInfo {
    /// Create a new ColumnInfo.
    pub fn new(name: String, type_name: String, nullable: bool) -> Self {
        ColumnInfo {
            name,
            type_name,
            nullable,
            precision: None,
            scale: None,
        }
    }

    /// Create a ColumnInfo with precision and scale (for DECIMAL, NUMERIC types).
    pub fn with_precision(
        name: String,
        type_name: String,
        nullable: bool,
        precision: u16,
        scale: u16,
    ) -> Self {
        ColumnInfo {
            name,
            type_name,
            nullable,
            precision: Some(precision),
            scale: Some(scale),
        }
    }
}
