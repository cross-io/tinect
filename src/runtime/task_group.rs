//! Small owner for a service's sibling tasks.
//!
//! This is intentionally a thin wrapper around `JoinSet`.  It gives a service
//! one cancellation token and one join boundary without introducing an actor,
//! task state machine, or global scheduler.

use std::{future::Future, time::Duration};
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

pub struct TaskGroup<T> {
    cancellation: CancellationToken,
    tasks: JoinSet<T>,
}

impl<T: Send + 'static> Default for TaskGroup<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + 'static> TaskGroup<T> {
    pub fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            tasks: JoinSet::new(),
        }
    }

    pub fn token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn spawn<F>(&mut self, task: F)
    where
        F: Future<Output = T> + Send + 'static,
    {
        self.tasks.spawn(task);
    }

    pub async fn join_next(&mut self) -> Option<Result<T, JoinError>> {
        self.tasks.join_next().await
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub async fn shutdown(mut self, timeout: Duration) -> Result<(), String> {
        self.cancel();
        let wait = async {
            let mut first_error = None;
            while let Some(result) = self.tasks.join_next().await {
                if let Err(error) = result
                    && first_error.is_none()
                {
                    first_error = Some(error.to_string());
                }
            }
            first_error.map_or(Ok(()), Err)
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(result) => result,
            Err(_) => {
                let remaining = self.tasks.len();
                self.tasks.abort_all();
                while self.tasks.join_next().await.is_some() {}
                Err(format!(
                    "task group shutdown timed out with {remaining} task(s)"
                ))
            }
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn cancellation_is_visible_to_children_and_shutdown_joins_them() {
        let mut group = TaskGroup::<()>::new();
        let stopped = Arc::new(AtomicBool::new(false));
        let child_stopped = stopped.clone();
        let token = group.token();
        group.spawn(async move {
            token.cancelled().await;
            child_stopped.store(true, Ordering::Release);
        });

        assert_eq!(group.len(), 1);
        assert!(!group.is_empty());
        group.shutdown(Duration::from_secs(1)).await.unwrap();
        assert!(stopped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn child_join_errors_are_returned() {
        let mut group = TaskGroup::<()>::new();
        group.spawn(async { panic!("test task failure") });
        let error = group.shutdown(Duration::from_secs(1)).await.unwrap_err();
        assert!(error.contains("panicked"));
    }

    #[tokio::test]
    async fn panic_drains_siblings_before_returning_error() {
        let mut group = TaskGroup::<()>::new();
        let sibling_started = Arc::new(tokio::sync::Notify::new());
        let sibling_cleaned = Arc::new(AtomicBool::new(false));
        let token = group.token();
        let started = sibling_started.clone();
        let cleaned = sibling_cleaned.clone();
        group.spawn(async move {
            started.notify_one();
            token.cancelled().await;
            tokio::time::sleep(Duration::from_millis(25)).await;
            cleaned.store(true, Ordering::Release);
        });
        sibling_started.notified().await;
        group.spawn(async { panic!("test task failure") });

        let error = group.shutdown(Duration::from_secs(1)).await.unwrap_err();
        assert!(error.contains("panicked"));
        assert!(sibling_cleaned.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn timeout_aborts_a_child_that_ignores_cancellation() {
        let mut group = TaskGroup::<()>::new();
        group.spawn(async {
            std::future::pending::<()>().await;
        });
        let error = group.shutdown(Duration::from_millis(1)).await.unwrap_err();
        assert!(error.contains("timed out"));
    }

    #[test]
    fn task_group_default_constructs_empty() {
        let group = TaskGroup::<()>::default();
        assert!(group.is_empty());
        assert_eq!(group.len(), 0);
    }
}
