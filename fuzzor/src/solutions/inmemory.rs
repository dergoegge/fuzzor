use std::collections::HashMap;

use crate::solutions::{Solution, SolutionStore};

#[derive(Default)]
pub struct InMemorySolutionStore {
    solutions: HashMap<String, Solution>,
}

impl SolutionStore for InMemorySolutionStore {
    fn store(&mut self, solution: Solution) -> bool {
        self.solutions
            .insert(solution.id().to_string(), solution)
            .is_none()
    }

    fn get(&self, id: &str) -> Option<&Solution> {
        self.solutions.get(id)
    }
}
