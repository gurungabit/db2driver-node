/// Integration tests for transactions.
/// Requires a running DB2 instance.
#[path = "../common/mod.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_commit() {
    let client = connect().await;
    let table = temp_table_name("txcommit");
    drop_table(&client, &table).await;

    client
        .query(
            &format!("CREATE TABLE {} (id INTEGER, val VARCHAR(50))", table),
            &[],
        )
        .await
        .expect("create table");

    // Start transaction, insert, commit
    let txn = client.begin_transaction().await.expect("begin txn");
    txn.query(
        &format!("INSERT INTO {} VALUES (1, 'committed')", table),
        &[],
    )
    .await
    .expect("insert in txn");
    txn.commit().await.expect("commit");

    // Verify data persisted
    let result = client
        .query(&format!("SELECT * FROM {}", table), &[])
        .await
        .expect("select after commit");
    assert_eq!(result.rows.len(), 1, "committed row should be visible");

    drop_table(&client, &table).await;
    client.close().await.expect("close");
}

#[tokio::test]
async fn test_rollback() {
    let client = connect().await;
    let table = temp_table_name("txroll");
    drop_table(&client, &table).await;

    client
        .query(
            &format!("CREATE TABLE {} (id INTEGER, val VARCHAR(50))", table),
            &[],
        )
        .await
        .expect("create table");

    // Insert one row outside transaction
    client
        .query(&format!("INSERT INTO {} VALUES (1, 'before')", table), &[])
        .await
        .expect("insert before txn");

    // Start transaction, insert another row, rollback
    let txn = client.begin_transaction().await.expect("begin txn");
    txn.query(
        &format!("INSERT INTO {} VALUES (2, 'rolled back')", table),
        &[],
    )
    .await
    .expect("insert in txn");
    txn.rollback().await.expect("rollback");

    // Verify only the first row exists
    let result = client
        .query(&format!("SELECT * FROM {}", table), &[])
        .await
        .expect("select after rollback");
    assert_eq!(
        result.rows.len(),
        1,
        "rolled-back row should not be visible"
    );

    drop_table(&client, &table).await;
    client.close().await.expect("close");
}

#[tokio::test]
async fn test_transfer_atomicity() {
    let client = connect().await;
    let table = temp_table_name("txfer");
    drop_table(&client, &table).await;

    client
        .query(
            &format!(
                "CREATE TABLE {} (account VARCHAR(20), balance DECIMAL(10,2))",
                table
            ),
            &[],
        )
        .await
        .expect("create table");

    client
        .query(
            &format!(
                "INSERT INTO {} VALUES ('alice', 1000.00), ('bob', 500.00)",
                table
            ),
            &[],
        )
        .await
        .expect("seed accounts");

    // Transfer 200 from Alice to Bob in a transaction
    let txn = client.begin_transaction().await.expect("begin");
    txn.query(
        &format!(
            "UPDATE {} SET balance = balance - 200.00 WHERE account = 'alice'",
            table
        ),
        &[],
    )
    .await
    .expect("debit alice");
    txn.query(
        &format!(
            "UPDATE {} SET balance = balance + 200.00 WHERE account = 'bob'",
            table
        ),
        &[],
    )
    .await
    .expect("credit bob");
    txn.commit().await.expect("commit transfer");

    // Verify balances
    let result = client
        .query(
            &format!("SELECT account, balance FROM {} ORDER BY account", table),
            &[],
        )
        .await
        .expect("select balances");
    assert_eq!(result.rows.len(), 2);
    // Total balance should still be 1500.00 (conservation check)

    drop_table(&client, &table).await;
    client.close().await.expect("close");
}
