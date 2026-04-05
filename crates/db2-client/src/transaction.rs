use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::connection::ClientInner;
use crate::error::Error;
use crate::types::{QueryResult, ToSql};

/// A database transaction that groups multiple operations into an atomic unit.
///
/// If the Transaction is dropped without calling `commit()` or `rollback()`,
/// a warning is logged. In practice, the server will typically rollback
/// uncommitted work when the next statement executes or the connection closes.
pub struct Transaction {
    inner: Arc<Mutex<ClientInner>>,
    committed: bool,
    rolled_back: bool,
}

impl Transaction {
    /// Create a new Transaction wrapping the given connection state.
    pub(crate) fn new(inner: Arc<Mutex<ClientInner>>) -> Self {
        debug!("Transaction started");
        Transaction {
            inner,
            committed: false,
            rolled_back: false,
        }
    }

    /// Execute a SQL query or statement within this transaction.
    pub async fn query(
        &self,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Result<QueryResult, Error> {
        if self.committed {
            return Err(Error::Other(
                "Transaction already committed".into(),
            ));
        }
        if self.rolled_back {
            return Err(Error::Other(
                "Transaction already rolled back".into(),
            ));
        }

        let mut guard = self.inner.lock().await;
        if !guard.connected {
            return Err(Error::Connection("Not connected".into()));
        }
        guard.execute_query(sql, params).await
    }

    /// Execute a SQL statement with no parameters within this transaction.
    pub async fn execute(&self, sql: &str) -> Result<QueryResult, Error> {
        self.query(sql, &[]).await
    }

    /// Commit the transaction, making all changes permanent.
    /// Consumes the Transaction.
    pub async fn commit(mut self) -> Result<(), Error> {
        if self.committed {
            return Err(Error::Other(
                "Transaction already committed".into(),
            ));
        }
        if self.rolled_back {
            return Err(Error::Other(
                "Transaction already rolled back".into(),
            ));
        }

        let mut guard = self.inner.lock().await;
        guard.commit().await?;
        self.committed = true;
        debug!("Transaction committed");
        Ok(())
    }

    /// Rollback the transaction, undoing all changes.
    /// Consumes the Transaction.
    pub async fn rollback(mut self) -> Result<(), Error> {
        if self.committed {
            return Err(Error::Other(
                "Transaction already committed".into(),
            ));
        }
        if self.rolled_back {
            return Err(Error::Other(
                "Transaction already rolled back".into(),
            ));
        }

        let mut guard = self.inner.lock().await;
        guard.rollback().await?;
        self.rolled_back = true;
        debug!("Transaction rolled back");
        Ok(())
    }

    /// Check if this transaction has been committed.
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Check if this transaction has been rolled back.
    pub fn is_rolled_back(&self) -> bool {
        self.rolled_back
    }

    /// Check if this transaction is still active (not committed or rolled back).
    pub fn is_active(&self) -> bool {
        !self.committed && !self.rolled_back
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed && !self.rolled_back {
            warn!(
                "Transaction dropped without commit or rollback. \
                 The server may hold locks until the connection is closed or \
                 a subsequent commit/rollback occurs."
            );
            // Cannot perform async rollback in Drop.
            // The connection's next operation or close will handle cleanup.
        }
    }
}
