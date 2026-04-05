use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("SQL error (SQLSTATE={sqlstate}, SQLCODE={sqlcode}): {message}")]
    Sql {
        sqlstate: String,
        sqlcode: i32,
        message: String,
    },

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Pool error: {0}")]
    Pool(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn is_auth_error(&self) -> bool {
        matches!(self, Error::Auth(_))
    }

    pub fn sqlstate(&self) -> Option<&str> {
        match self {
            Error::Sql { sqlstate, .. } => Some(sqlstate),
            _ => None,
        }
    }

    pub fn sqlcode(&self) -> Option<i32> {
        match self {
            Error::Sql { sqlcode, .. } => Some(*sqlcode),
            _ => None,
        }
    }
}

impl From<db2_proto::ProtoError> for Error {
    fn from(e: db2_proto::ProtoError) -> Self {
        Error::Protocol(e.to_string())
    }
}
