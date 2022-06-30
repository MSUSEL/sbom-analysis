mod format;

#[macro_use]
extern crate serde;

#[macro_use]
extern crate tokio;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use dotenv::dotenv;
use neo4rs::{Config, config, ConfigBuilder, Graph, query};

#[tokio::main]
async fn main() {
    dotenv().ok();

    // let uri = std::env::var("NEO4J_URI").expect("NEO4J_URI is not set");
    // let username = std::env::var("NEO4J_USERNAME").expect("NEO4J_USERNAME is not set");
    // let password = std::env::var("NEO4J_PASSWORD").expect("NEO4J_PASSWORD is not set");
    // let database = std::env::var("AURA_INSTANCENAME").expect("AURA_INSTANCENAME is not set");

    let uri = "127.0.0.1:7687";
    let username = "neo4j";
    let password = "reu2022";
    let database = "neo4j";

    let config = config()
        .uri(&uri)
        .user(&username)
        .password(&password)
        .db(&database)
        .fetch_size(10)
        .max_connections(5)
        .build()
        .unwrap();

    let graph = Arc::new(Graph::connect(config).await.unwrap());
    let id = 34;
    let mut result = graph.run(
        query("CREATE (p:Person {id: $id})").param("id", id.clone())
    ).await.unwrap();

    let mut handles = Vec::new();
    let mut count = Arc::new(AtomicU32::new(0));
    for _ in 1..=42 {
        let graph = graph.clone();
        let id = id.clone();
        let count = count.clone();
        let handle = tokio::spawn(async move {
            let mut result = graph.execute(
                query("MATCH (p:Person {id: $id}) RETURN p").param("id", id)
            ).await.unwrap();
            while let Ok(Some(row)) = result.next().await {
                count.fetch_add(1, Ordering::Relaxed);
                println!("{:?}", row);
            }
        });
        handles.push(handle);
    }

    futures::future::join_all(handles).await;
}
