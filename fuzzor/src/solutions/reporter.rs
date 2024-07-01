use std::future::Future;

use super::Solution;
use super::SolutionMetadata::{Crash, Differential, Timeout};

use octocrab::{models::repos::CommitAuthor, Octocrab};

pub trait SolutionReporter {
    fn report_new_solution(
        &mut self,
        project: String,
        harness: String,
        solution: Solution,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

/// A [`SolutionReporter`] that reports new solutions to a GitHub repository.
///
/// Solutions will be reported as an issue and the fuzz inputs are commited to the repository.
#[derive(Clone)]
pub struct GitHubRepoSolutionReporter {
    github: octocrab::Octocrab,
    repo: String,
    owner: String,
    ccs: Vec<String>,
}

impl GitHubRepoSolutionReporter {
    pub fn new(owner: &str, repo: &str, access_token: &str, ccs: Vec<String>) -> Self {
        Self {
            github: Octocrab::builder()
                .personal_token(access_token.to_string())
                .build()
                .unwrap(),
            repo: repo.to_string(),
            owner: owner.to_string(),
            ccs,
        }
    }
}

async fn upload_file_to_repo(
    github: &octocrab::Octocrab,
    owner: &str,
    repo: &str,
    msg: &str,
    file_path: &str,
    file_contents: &[u8],
) -> Result<octocrab::models::repos::Content, String> {
    Ok(github
        .repos(owner, repo)
        .create_file(file_path, msg, file_contents)
        .branch("main")
        .author(CommitAuthor {
            name: "fuzzor".to_string(),
            email: "niklas@brink.dev".to_string(),
            date: None,
        })
        .commiter(CommitAuthor {
            name: "fuzzor".to_string(),
            email: "niklas@brink.dev".to_string(),
            date: None,
        })
        .send()
        .await
        .map_err(|e| {
            if let octocrab::Error::GitHub {
                source,
                backtrace: _,
            } = e
            {
                format!("Could not create file in repo ({}): {}", file_path, source)
            } else {
                format!("Could not create file in repo ({}): {:?}", file_path, e)
            }
        })?
        .content)
}

impl SolutionReporter for GitHubRepoSolutionReporter {
    async fn report_new_solution(
        &mut self,
        project: String,
        harness: String,
        solution: Solution,
    ) -> Result<(), String> {
        let test_case_path = format!(
            "solutions/{}/{}/solution-{}",
            project,
            harness,
            solution.id()
        );

        // Check if the this solution was already reported by checking if the input file exists in
        // the repo.
        //
        // TODO: this should be persisted locally, so we don't need to query github.
        if let Ok(content) = self
            .github
            .repos(&self.owner, &self.repo)
            .get_content()
            .path(&test_case_path)
            .r#ref("main")
            .send()
            .await
        {
            log::warn!(
                "Not reporting solution as it already exists: {}",
                content.items[0].path
            );
            return Ok(());
        }

        // Upload the solutions' input to the repository
        let input_url = upload_file_to_repo(
            &self.github,
            &self.owner,
            &self.repo,
            &format!(
                "[solutions] Upload input for {} solution={}",
                match solution.metadata {
                    Crash(_) => "crashing",
                    Timeout(_) => "timeout",
                    Differential(_) => "differential",
                },
                solution.id(),
            ),
            &test_case_path,
            solution.input_bytes(),
        )
        .await?
        .html_url
        .unwrap();

        let flame_graph_url = match solution.metadata() {
            // Upload the flamegraph for timeouts
            Timeout(flamegraph) => upload_file_to_repo(
                &self.github,
                &self.owner,
                &self.repo,
                &format!("[flamegraphs] Upload flame graph for {} timeout", harness),
                &format!(
                    "flamegraphs/{}/{}/solution-{}.svg",
                    project,
                    harness,
                    solution.unique_id()
                ),
                flamegraph.as_bytes(),
            )
            .await?
            .html_url
            .unwrap(),
            _ => String::new(),
        };

        let label = match solution.metadata() {
            Crash(_) => String::from("Crash"),
            Timeout(_) => String::from("Timeout"),
            Differential(_) => String::from("Differential"),
        };

        // We include the base64 encoded input in the issue but only if it is less than 10KB.
        let base64 = solution.input_base64();
        let base64 = if base64.len() > 10000 {
            String::from("Base64 encoded input exceeds 10KB")
        } else {
            base64
        };

        // Open issue
        self.github
            .issues(&self.owner, &self.repo)
            .create(format!("{}: {} in `{}`", project, label, harness))
            .body(match solution.metadata() {
                Crash(stack_trace) | Differential(stack_trace) => format!(
                    "Deduplication key: {}\n\nTest case: {}\nBase64: \n```\n{}\n```\n\nStacktrace:\n ```\n{}```\n",
                    solution.id(), input_url, base64, stack_trace
                ),
                Timeout(_) => format!(
                    "Deduplication key: {}\n\nTest case: {}\nBase64: \n```\n{}\n```\n\nFlame Graph: {}\n",
                    solution.id(),
                    input_url,
                    base64,
                    flame_graph_url,
                ),
            })
            .labels(vec![label])
            .assignees(self.ccs.clone())
            .send()
            .await
            .map_err(|e| format!("Could not create issue for new solution: {}", e))?;

        log::info!(
            "Reported solution ({}) to GitHub repo {}/{}",
            solution.id(),
            self.owner,
            self.repo
        );
        Ok(())
    }
}
