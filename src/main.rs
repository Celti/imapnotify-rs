use anyhow::bail;
use anyhow::{Context, Error, Result};
use native_tls::{TlsConnector, TlsStream};
use rayon::iter::{ParallelIterator, IntoParallelRefIterator};
use serde::Deserialize;
use toml::Value;

use std::collections::{HashMap, HashSet};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use std::thread;
use std::borrow::Cow;

#[derive(Clone, Debug, Deserialize)]
struct Account<'a> {
    host: Cow<'a, str>,
    #[serde(default = "Account::default_port")]
    port: u16,
    #[serde(default = "Account::default_starttls")]
    starttls: bool,
    username: Cow<'a, str>,
    password: Cow<'a, str>,
    on_new_mail: Cow<'a, str>,
    on_new_mail_post: Option<Cow<'a, str>>,
    #[serde(borrow)]
    boxes: Cow<'a, [Cow<'a, str>]>,
}

#[derive(Clone, Debug, Deserialize)]
struct Config<'b> {
    #[serde(borrow)]
    #[serde(flatten)]
    accounts: HashMap<String, Account<'b>>,
}

struct Connection<'c, 'a: 'c> {
    account: &'c Account<'a>,
    session: imap::Session<TlsStream<TcpStream>>,
}

impl<'a> Account<'a> {
    const fn default_starttls() -> bool { true }
    const fn default_port() -> u16 { 143 }

}

        let tls = TlsConnector::builder().build()?;
impl<'a: 'b, 'b> Connection<'a, 'b> {
    fn new<'c: 'a>(account: &'a Account<'a>) -> Result<Connection<'c, 'a>, imap::error::Error> {

        let client = if account.starttls {
            imap::connect_insecure((&*account.host, account.port))?.secure(&*account.host, &tls)?
        } else {
            imap::connect((&*account.host, account.port), &*account.host, &tls)?
        }; // I considered putting a check to allow unencrypted connections here, but... why?

        let mut session = client.login(account.username.trim(), account.password.trim()).map_err(|(e, _)| e)?;
        let cap = session.capabilities()?;

        if !cap.iter().any(|&c| c == "IDLE") {
            return Err(imap::error::Error::Bad(cap.iter().cloned().collect()));
        }

        session.examine(&account.boxes[0])?;

        Ok(Connection {
            account: &account,
            session,
        })
    }

    fn idle_loop(&mut self) -> Result<()> {
        let mut last = 0;
        let command = &*self.account.on_new_mail;
        let command_post = self.account.on_new_mail_post.as_deref();

        loop {
            let mut uids = HashSet::new();

            for mbox in &*self.account.boxes {
                self.session.examine(mbox)?;
                let search = self.session.uid_search("NEW 1:*")?;
                uids.extend(search);
            }

            if uids.iter().all(|&uid| uid > last) {
                // New mail, let's run!
                let scope = crossbeam::scope(|s| {
                    s.spawn(move |_| {
                        if let Err(e) = Command::new("/bin/sh").arg("-c").arg(command).spawn() {
                            eprintln!("Command failed: {}", e);
                        } else if let Some(command) = command_post {
                            if let Err(e) = Command::new("/bin/sh").arg("-c").arg(command).spawn() {
                                eprintln!("Command failed: {}", e);
                            }
                        }
                    });
                });

                if let Err(any) = scope {
                    match any.downcast::<Error>() {
                        Ok(error) => return Err(*error),
                        Err(any)  => bail!("unexpected threading error: {:?}", any),
                    }
                };
            } else {
                uids.clear();
            }

            last = std::cmp::max(last, uids.iter().cloned().max().unwrap_or(0));

            self.session.idle()?.wait_keepalive()?;
        }
    }

    fn run(&mut self) {
        loop {
            if let Err(e) = self.idle_loop() {
                eprintln!("Connection to {} failed: {}.", self.account.host, e);
                let _ = self.session.logout(); // This will probably fail, so ignore any error.
                break;
            }
        }

        let mut wait = 1;
        for _try in 0..5 {
            match Connection::new(self.account) {
                Err(e) => {
                    eprintln!("Connection to {} failed: {}. Retrying in {} seconds.", self.account.host, e, wait);
                    thread::sleep(Duration::from_secs(wait));
                    wait *= 2;
                }
                Ok(mut c) => {
                    eprintln!("Connection for {} reestablished.", self.account.host);
                    return c.run();
                }
            }
        }
    }

}

fn preprocess_toml(t: &mut Value) {
    let table = match t.as_table_mut() {
        Some(table) => table,
        None => return,
    };

    // Recurse on all table entries.
    for (_, v) in &mut *table {
        preprocess_toml(v)
    };

    if dbg!(table.contains_key("password_eval")) {
        let value    = table.remove("password_eval").unwrap();
        let fallback = table.remove("password");

        let password = if let Some(eval) = value.as_str() {
            match Command::new("/bin/sh").arg("-c").arg(eval).output() {
                Err(e) => { eprintln!("Password eval failed: {}", e); None },
                Ok(child) => match std::str::from_utf8(&child.stdout) {
                    Err(e) => { eprintln!("Password eval failed: {}", e); None },
                    Ok(string) => Some(Value::from(string)),
                }
            }
        } else if fallback.is_some() {
            fallback
        } else if let Ok(tty) = rpassword::read_password_from_tty(Some("Password: ")) {
            Some(Value::from(tty))
        } else {
            None
        };

        password.and_then(|v| table.insert("password".to_string(), v));
    };
}

fn configure<'a>() -> Result<Vec<Account<'a>>> {
    let xdg = xdg::BaseDirectories::new()?;
    let path = xdg.find_config_file("imapnotify.toml").context("file not found")?;
    let file = std::fs::read_to_string(path)?;

    let mut toml: Value = toml::from_str(&file)?;
    preprocess_toml(&mut toml);
    let config = toml.try_into::<Config>()?;

    if config.accounts.is_empty() {
        bail!("no accounts in imapnotify.toml");
    }

    let accounts = config.accounts.into_iter().map(|(_k,v)|v).collect();

    Ok(accounts)
}

fn main() -> Result<()> {
    let config = configure().context("Could not process configuration file imapnotify.toml")?;

    let connections: Vec<_> = config.par_iter().filter_map(|account| {
        let mut wait = 1;
        for _try in 0..5 {
            match Connection::new(account) {
                Ok(c) => return Some(c),
                Err(e) => {
                    eprintln!("Connection to {} failed: {}. Retrying in {} seconds.", account.host, e, wait);
                    thread::sleep(Duration::from_secs(wait));
                    wait *= 2;
                }
            }
        }

        None // tries exceeded.
    }).collect();

    if connections.is_empty() {
        bail!("could not establish any connections");
    }

    let scope = crossbeam::scope(move |s| {
        for mut connection in connections {
            s.spawn(move |_| {
                connection.run();
            });
        }
    });

    if let Err(any) = scope {
        match any.downcast::<Error>() {
            Ok(error) => return Err(*error),
            Err(any)  => bail!("unexpected threading error: {:?}", any),
        }
    };

    Ok(())
}
