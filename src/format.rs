use std::{cmp::max, collections::HashMap};

use anyhow::Result;

#[derive(PartialEq, Eq)]
enum Value {
    Seperator,
    NewLine,
    Entry(String, String),
}

/// Simple helper to print key-value entries where the keys are all alligned.
///
/// Here is an example of how it looks:
///
/// --------------------------------------------------------------------------
/// account 0: fuel12sdaglkadsgmoaeigm49309k403ydxtqmzuaqtzdjlsww5t2jmg9skutn8n
/// Asset ID : 0000000000000000000000000000000000000000000000000000000000000000
/// Amount   : 499999800
///
/// Asset ID : 0000000000000000000000000000000000000000000000000000000000000001
/// Amount   : 359989610
/// --------------------------------------------------------------------------
/// account 1: fuel29asdfjoiajg934344iw9e8jfasoiaeigjaergokjaeoigjaeg9ij39ijg34
/// Asset ID : 0000000000000000000000000000000000000000000000000000000000000000
/// Amount   : 268983615
#[derive(Default)]
pub struct List(Vec<Value>);

impl List {
    pub fn add(&mut self, title: impl ToString, value: impl ToString) {
        self.0
            .push(Value::Entry(title.to_string(), value.to_string()));
    }

    pub fn add_newline(&mut self) {
        self.0.push(Value::NewLine);
    }

    pub fn add_seperator(&mut self) {
        if self.0.last() == Some(&Value::Seperator) {
            return;
        }
        self.0.push(Value::Seperator);
    }

    pub fn longest_title(&self) -> usize {
        self.0
            .iter()
            .map(|value| match value {
                Value::Seperator => 0,
                Value::NewLine => 0,
                Value::Entry(title, _) => title.len(),
            })
            .max()
            .unwrap_or(0)
    }
}

impl ToString for List {
    fn to_string(&self) -> String {
        let longest_key = self.longest_title();
        let entries = self
            .0
            .iter()
            .map(|entry| match entry {
                Value::Seperator => None,
                Value::NewLine => Some("".to_owned()),
                Value::Entry(title, value) => {
                    let padding = " ".repeat(longest_key - title.len());
                    Some(format!("{}{}: {}", title, padding, value))
                }
            })
            .collect::<Vec<_>>();

        let longest_entry = entries
            .iter()
            .map(|entry| entry.as_ref().map(|s| s.len()).unwrap_or(0))
            .max()
            .unwrap_or(0);

        let seperator = "-".repeat(longest_entry);

        entries
            .into_iter()
            .map(|entry| entry.map(|s| s.to_string()).unwrap_or(seperator.clone()))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Default)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn add_header(&mut self, header: impl ToString) {
        self.headers.push(header.to_string());
    }

    pub fn add_row(&mut self, row: Vec<impl ToString>) -> Result<()> {
        if self.headers.len() != row.len() {
            anyhow::bail!("Row length does not match header length");
        }
        self.rows
            .push(row.into_iter().map(|x| x.to_string()).collect());
        Ok(())
    }
}
impl ToString for Table {
    fn to_string(&self) -> String {
        let mut longest_columns = self
            .headers
            .iter()
            .enumerate()
            .map(|(column_id, x)| (column_id, x.len()))
            .collect::<HashMap<_, _>>();

        for row in self.rows.iter() {
            for (column_id, value) in row.iter().enumerate() {
                longest_columns
                    .entry(column_id)
                    .and_modify(|x| *x = max(*x, value.len()));
            }
        }
        let separator = self
            .headers
            .iter()
            .enumerate()
            .map(|(column_id, _)| "-".repeat(longest_columns[&column_id]))
            .collect::<Vec<_>>()
            .join("-|-");

        let mut table = vec![
            self.headers
                .iter()
                .enumerate()
                .map(|(column_id, header)| {
                    let padding = " ".repeat(longest_columns[&column_id] - header.len());
                    format!("{}{}", header, padding)
                })
                .collect::<Vec<_>>()
                .join(" | "),
            separator.clone(),
        ];

        for row in &self.rows {
            table.push(
                row.iter()
                    .enumerate()
                    .map(|(column_id, value)| {
                        let padding = " ".repeat(longest_columns[&column_id] - value.len());
                        format!("{}{}", value, padding)
                    })
                    .collect::<Vec<_>>()
                    .join(" | "),
            );
            table.push(separator.clone());
        }

        table.join("\n")
    }
}
