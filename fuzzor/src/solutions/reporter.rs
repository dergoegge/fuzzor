use std::future::Future;

use super::Solution;

pub trait SolutionReporter {
    fn report_new_solution(
        &mut self,
        project: String,
        harness: String,
        solution: Solution,
    ) -> impl Future<Output = Result<(), String>> + Send;
}
