use std::collections::HashMap;

use crate::solutions::{Solution, SolutionTracker};

#[derive(Default)]
pub struct InMemorySolutionTracker {
    solutions: HashMap<String, Solution>,
}

impl SolutionTracker for InMemorySolutionTracker {
    fn mark_as_resolved(&mut self, id: &str) -> Option<Solution> {
        self.solutions.remove(id)
    }

    fn submit(&mut self, solution: Solution) -> bool {
        // Note: this will overwrite the old solution
        self.solutions
            .insert(solution.id().to_string(), solution)
            .is_none()
    }

    fn get_open(&self, id: &str) -> Option<&Solution> {
        self.solutions.get(id)
    }

    fn get_all(&self) -> Vec<Solution> {
        self.solutions.values().map(|s| s.clone()).collect()
    }
}
