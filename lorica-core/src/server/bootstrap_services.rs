// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(unix)]
pub use super::transfer_fd::Fds;
use async_trait::async_trait;
#[cfg(unix)]
use log::{debug, error};
use log::info;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::broadcast;
#[cfg(unix)]
use tokio::sync::Mutex as TokioMutex;

#[cfg(unix)]
use crate::server::ListenFds;

use crate::{
    prelude::Opt,
    server::{configuration::ServerConf, ExecutionPhase, ShutdownWatch},
    services::{background::BackgroundService, ServiceReadyNotifier},
};

/// Service that allows the bootstrap process to be delayed until after
/// dependencies are ready
pub struct BootstrapService {
    inner: Arc<Mutex<Bootstrap>>,
}

impl BootstrapService {
    pub fn new(inner: &Arc<Mutex<Bootstrap>>) -> Self {
        BootstrapService {
            inner: Arc::clone(inner),
        }
    }
}

/// Encapsulation of the data needed to bootstrap the server
pub struct Bootstrap {
    completed: bool,

    test: bool,
    _upgrade: bool,

    _upgrade_sock: String,

    execution_phase_watch: broadcast::Sender<ExecutionPhase>,

    #[cfg(unix)]
    listen_fds: Option<ListenFds>,
}

impl Bootstrap {
    pub fn new(
        options: &Option<Opt>,
        conf: &ServerConf,
        execution_phase_watch: &broadcast::Sender<ExecutionPhase>,
    ) -> Self {
        let (test, upgrade) = options
            .as_ref()
            .map(|opt| (opt.test, opt.upgrade))
            .unwrap_or_default();

        let upgrade_sock = conf.upgrade_sock.clone();

        Bootstrap {
            test,
            _upgrade: upgrade,
            _upgrade_sock: upgrade_sock,
            #[cfg(unix)]
            listen_fds: None,
            execution_phase_watch: execution_phase_watch.clone(),
            completed: false,
        }
    }

    pub fn bootstrap(&mut self) {
        // already bootstrapped
        if self.completed {
            return;
        }

        info!("Bootstrap starting");

        self.execution_phase_watch
            .send(ExecutionPhase::Bootstrap)
            .ok();

        if self.test {
            info!("Server Test passed, exiting");
            std::process::exit(0);
        }

        // load fds
        #[cfg(unix)]
        match self.load_fds(self._upgrade) {
            Ok(_) => {
                info!("Bootstrap done");
            }
            Err(e) => {
                error!("Bootstrap failed on error: {:?}, exiting.", e);
                std::process::exit(1);
            }
        }

        self.completed = true;

        self.execution_phase_watch
            .send(ExecutionPhase::BootstrapComplete)
            .ok();
    }

    #[cfg(unix)]
    fn load_fds(&mut self, upgrade: bool) -> Result<(), nix::errno::Errno> {
        let mut fds = Fds::new();
        if upgrade {
            debug!("Trying to receive socks");
            fds.get_from_sock(self._upgrade_sock.as_str())?
        }
        self.listen_fds = Some(Arc::new(TokioMutex::new(fds)));
        Ok(())
    }

    #[cfg(unix)]
    pub fn get_fds(&self) -> Option<ListenFds> {
        self.listen_fds.clone()
    }
}

#[async_trait]
impl BackgroundService for BootstrapService {
    async fn start_with_ready_notifier(
        &self,
        _shutdown: ShutdownWatch,
        notifier: ServiceReadyNotifier,
    ) {
        self.inner.lock().bootstrap();
        notifier.notify_ready();
    }
}
