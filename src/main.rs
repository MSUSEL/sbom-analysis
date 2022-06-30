mod format;
mod vulnerability;

#[macro_use]
extern crate serde;

extern crate tokio;

use std::sync::Arc;
use dotenv::dotenv;
use neo4rs::{config, Graph, query};

async fn establish_graph() -> Graph {
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

    Graph::connect(config).await.unwrap()
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // let uri = std::env::var("NEO4J_URI").expect("NEO4J_URI is not set");
    // let username = std::env::var("NEO4J_USERNAME").expect("NEO4J_USERNAME is not set");
    // let password = std::env::var("NEO4J_PASSWORD").expect("NEO4J_PASSWORD is not set");
    // let database = std::env::var("AURA_INSTANCENAME").expect("AURA_INSTANCENAME is not set");



    let graph = Arc::new(establish_graph().await);
    let id = 34;
    graph.run(
        query("CREATE (p:Person {id: $id})").param("id", id.clone())
    ).await.unwrap();

    let mut handles = Vec::new();
    for _ in 1..=42 {
        let graph = graph.clone();
        let id = id.clone();
        let handle = tokio::spawn(async move {
            let mut result = graph.execute(
                query("MATCH (p:Person {id: $id}) RETURN p").param("id", id)
            ).await.unwrap();
            while let Ok(Some(_)) = result.next().await {
            }
        });
        handles.push(handle);
    }

    futures::future::join_all(handles).await;
}
