//! Runs `tunmux::api` calls off the UI thread, one at a time, so a connect
//! and the disconnect that precedes a replace never race.

use std::sync::mpsc::{self, Receiver, Sender};

use tunmux::api::{self, AccountInfo, ConnectSpec, Credentials, LoginOutcome, ServerInfo};
use tunmux::config::Provider;

use crate::live::Notify;

pub enum Job {
    Accounts,
    Servers(Provider),
    Login(Provider, Credentials),
    Logout(Provider),
    Connect(Provider, ConnectSpec),
    /// Disconnect `instance`, then connect: replaces a running instance.
    Replace(String, Provider, ConnectSpec),
    Disconnect(String),
    DisconnectAll,
}

pub enum Event {
    Accounts(Vec<AccountInfo>),
    Servers(Provider, Result<Vec<ServerInfo>, String>),
    Login(Provider, Result<LoginOutcome, String>),
    /// Outcome of an action, shown as a toast.
    Done(Result<String, String>),
    /// A job finished; the next one may start.
    Idle,
}

pub struct Worker {
    jobs: Sender<Job>,
    events: Receiver<Event>,
    pending: usize,
}

impl Worker {
    pub fn start(notify: Notify) -> Self {
        let (jobs, job_rx) = mpsc::channel::<Job>();
        let (event_tx, events) = mpsc::channel();
        std::thread::Builder::new()
            .name("tunmux-gui-worker".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(error) => {
                        let _ = event_tx.send(Event::Done(Err(format!(
                            "cannot start the async runtime: {error}"
                        ))));
                        notify();
                        return;
                    }
                };
                let config = tunmux::config::load_config();
                for job in job_rx {
                    for event in runtime.block_on(run(job, &config)) {
                        let _ = event_tx.send(event);
                    }
                    let _ = event_tx.send(Event::Idle);
                    notify();
                }
            })
            .expect("spawn worker thread");
        Self {
            jobs,
            events,
            pending: 0,
        }
    }

    pub fn send(&mut self, job: Job) {
        if self.jobs.send(job).is_ok() {
            self.pending += 1;
        }
    }

    pub fn is_busy(&self) -> bool {
        self.pending > 0
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        let events: Vec<Event> = self.events.try_iter().collect();
        let idle = events.iter().filter(|e| matches!(e, Event::Idle)).count();
        self.pending = self.pending.saturating_sub(idle);
        events
    }
}

async fn run(job: Job, config: &tunmux::config::AppConfig) -> Vec<Event> {
    let text = |e: anyhow::Error| format!("{e:#}");
    match job {
        Job::Accounts => vec![Event::Accounts(api::accounts(config))],
        Job::Servers(p) => vec![Event::Servers(
            p,
            api::servers(p, config).await.map_err(text),
        )],
        Job::Login(p, credentials) => vec![
            Event::Login(p, api::login(p, &credentials, config).await.map_err(text)),
            Event::Accounts(api::accounts(config)),
        ],
        Job::Logout(p) => vec![
            Event::Done(
                api::logout(p, config)
                    .await
                    .map(|()| format!("Logged out of {}", p.label()))
                    .map_err(text),
            ),
            Event::Accounts(api::accounts(config)),
        ],
        Job::Connect(p, spec) => vec![Event::Done(connect(p, &spec, config).await)],
        Job::Replace(instance, p, spec) => {
            if let Err(error) = api::disconnect(&instance, config).await {
                return vec![Event::Done(Err(format!(
                    "cannot replace {instance}: {}",
                    text(error)
                )))];
            }
            vec![Event::Done(connect(p, &spec, config).await)]
        }
        Job::Disconnect(instance) => vec![Event::Done(
            api::disconnect(&instance, config)
                .await
                .map(|()| format!("Disconnected {instance}"))
                .map_err(text),
        )],
        Job::DisconnectAll => vec![Event::Done(
            api::disconnect_all(config)
                .await
                .map(|()| "Disconnected all".to_string())
                .map_err(text),
        )],
    }
}

async fn connect(
    p: Provider,
    spec: &ConnectSpec,
    config: &tunmux::config::AppConfig,
) -> Result<String, String> {
    let target = spec.server.clone().unwrap_or_else(|| p.label().to_string());
    api::connect(p, spec, config)
        .await
        .map(|()| format!("Connected {target}"))
        .map_err(|e| format!("{target}: {e:#}"))
}
