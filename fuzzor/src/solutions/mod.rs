pub mod inmemory;
pub mod reporter;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha1::{Digest, Sha1};

#[derive(Clone, Debug)]
pub enum SolutionMetadata {
    /// Crashes come with stack trace
    Crash(String),
    /// Timeouts come with a flamegraph
    Timeout(String),

    Differential(String),
}

/// Solution holds information about an interesting fuzz input.
#[derive(Clone, Debug)]
pub struct Solution {
    id: String,
    unique_id: String,
    input_bytes: Vec<u8>,

    metadata: SolutionMetadata,
}

impl Solution {
    pub fn from_differential_solution(input_bytes: Vec<u8>, stderr: String) -> Self {
        let unique_id = Solution::create_unique_id(&input_bytes);
        Self {
            id: String::from("differential"),
            unique_id,
            input_bytes,
            metadata: SolutionMetadata::Differential(stderr),
        }
    }

    /// Create a new solution from a crashing fuzz input and the crash's stack trace.
    pub fn from_crash(input_bytes: Vec<u8>, stack_trace: String) -> Self {
        let unique_id = Solution::create_unique_id(&input_bytes);

        // Fallback to "crash" as deduplication id if the stack trace does not appear to be a
        // libFuzzer trace.
        let id =
            deduplication_id_from_libfuzzer_trace(&stack_trace).unwrap_or(String::from("crash"));

        Self {
            id,
            unique_id,
            input_bytes,
            metadata: SolutionMetadata::Crash(stack_trace),
        }
    }

    /// Create a new solution from a fuzz input that times out.
    pub fn from_timeout(input_bytes: Vec<u8>, flamegraph: String) -> Self {
        Self {
            // Deduplicating timeouts is hard since there is no stack trace, so we'll just use
            // "timeout" as the deduplication identifier. This will mean that we will only track
            // one type of timeout per harness.
            id: String::from("timeout"),
            unique_id: Solution::create_unique_id(&input_bytes),
            input_bytes,
            metadata: SolutionMetadata::Timeout(flamegraph),
        }
    }

    /// Deduplication identifier for a solution.
    ///
    /// This identifier will be the same for solutions of the same kind. For example, there might
    /// be more than one fuzz input that triggers the same crash, in which case the identifier will
    /// be the same for deduplication purposes.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Unique identifier for a solution.
    ///
    /// This identifier is simply a hash of the input bytes and will therefore be unique to each
    /// fuzz input.
    pub fn unique_id(&self) -> &str {
        &self.unique_id
    }
    /// Input bytes that trigger the solution when passed to the corresponding harness.
    pub fn input_bytes(&self) -> &[u8] {
        &self.input_bytes
    }
    /// Metadata associated with solution (e.g. stack trace for crashes).
    pub fn metadata(&self) -> &SolutionMetadata {
        &self.metadata
    }

    /// Returns the input bytes as a base64 encoded string.
    pub fn input_base64(&self) -> String {
        STANDARD.encode(self.input_bytes())
    }

    fn create_unique_id(input_bytes: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(input_bytes);
        hex::encode(hasher.finalize())
    }
}

pub trait SolutionTracker {
    /// Mark a solution as resolved (e.g. underlying bug was fixed).
    fn mark_as_resolved(&mut self, id: &str) -> Option<Solution>;
    /// Submit a solution to the tracker. Returns whether or this was a new solution.
    fn submit(&mut self, solution: Solution) -> bool;
    /// Retrieve an open solution from the tracker by its deduplication id.
    fn get_open(&self, id: &str) -> Option<&Solution>;
    /// Get all solutions in the tracker
    fn get_all(&self) -> Vec<Solution>;
}

// Split a string by `delim` while also ensuring that each split has an equal number of '(' and
// ')' characters.
//
// # Examples
//
// ```
// use fuzzor::solutions::balanced_bracket_split;
// assert_eq!(balanced_bracket_split("test_fn(const Foo&) ()", ' '), &["test_fn(const Foo&)", "()"]);
// ```
fn balanced_bracket_split(input: &str, delim: char) -> Vec<&str> {
    let mut result = Vec::new();
    let mut balance_parentheses = 0;
    let mut start = 0;

    for (i, c) in input.char_indices() {
        match c {
            '(' => balance_parentheses += 1,
            ')' => balance_parentheses -= 1,
            _ if c == delim && balance_parentheses == 0 => {
                if i > start {
                    result.push(&input[start..i]);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    // Include the last part if there's any
    if start < input.len() {
        result.push(&input[start..]);
    }

    result
}

/// Create a deduplication key for a libFuzzer crash stack trace.
///
/// Returns `Some(key)` on success otherwise `None` if the trace failed to parse.
fn deduplication_id_from_libfuzzer_trace(stack_trace: &str) -> Option<String> {
    let mut hasher = Sha1::new();
    let lines = stack_trace.lines();
    let mut hash = false;

    for line in lines {
        if line.contains("runtime error:")
            || line.contains("==ERROR")
            || line.contains("== ERROR")
            || line.contains("==WARNING")
        {
            hash = true;
        }

        if hash && line.starts_with("SUMMARY") {
            return Some(hex::encode(hasher.finalize()));
        }

        if hash && line.trim().starts_with('#') {
            let trace_split = balanced_bracket_split(line, ' ');
            if trace_split.len() > 3 && trace_split[2] == "in" {
                hasher.update(trace_split[3].as_bytes());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brace_split() {
        assert_eq!(
            balanced_bracket_split("test_fn(const Foo&) ()", ' '),
            &["test_fn(const Foo&)", "()"]
        );
        assert_eq!(balanced_bracket_split("( ) ()", ' '), &["( )", "()"]);
        assert_eq!(balanced_bracket_split("( () )", ' '), &["( () )"]);

        assert_eq!(
            balanced_bracket_split("#9 0xaaaac977bac8 in (anonymous namespace)::tx_package_eval_fuzz_target(Span<unsigned char const>) package_eval.cpp", ' '),
            &[
                "#9",
                "0xaaaac977bac8",
                "in",
                "(anonymous namespace)::tx_package_eval_fuzz_target(Span<unsigned char const>)",
                "package_eval.cpp"
            ]
        );

        assert_eq!(
            balanced_bracket_split(
                "#2 0xaaaac942ab5c in fuzzer::Fuzzer::CrashCallback() crtstuff.c",
                ' '
            ),
            &[
                "#2",
                "0xaaaac942ab5c",
                "in",
                "fuzzer::Fuzzer::CrashCallback()",
                "crtstuff.c"
            ]
        );

        // TODO
        //assert_eq!(
        //    balanced_bracket_split(
        //        "#11 0xaaaae0ed19e8 in std::basic_istream<char, std::char_traits<char>>& \
        //        boost::posix_time::operator>><char, std::char_traits<char>>(std::basic_istream<char, \
        //        std::char_traits<char>>&, boost::posix_time::ptime&) util.cpp",
        //        ' '
        //    ),
        //    &[
        //        "#11",
        //        "0xaaaae0ed19e8",
        //        "in",
        //        "std::basic_istream<char, std::char_traits<char>>& boost::posix_time::operator>><char, std::char_traits<char>>(std::basic_istream<char, std::char_traits<char>>&, boost::posix_time::ptime&)",
        //        "util.cpp",
        //    ]
        //);
    }

    #[test]
    fn crash_ids() {
        {
            let input = vec![0u8];
            let crash = Solution::from_crash(input, String::from(""));
            // Malformed stack trace uses unique id as id
            assert_eq!(crash.id(), "crash");
        }

        {
            let input = vec![0u8];
            let crash0 = Solution::from_crash(input, String::from("==ERROR\n\nSUMMARY"));
            assert_ne!(crash0.id(), crash0.unique_id());

            let input = vec![0u8];
            let crash1 = Solution::from_crash(input, String::from("== ERROR\n\nSUMMARY"));
            assert_ne!(crash1.id(), crash1.unique_id());

            let input = vec![1u8];
            let crash2 = Solution::from_crash(input, String::from("===WARNING\n\nSUMMARY"));
            assert_eq!(crash1.id(), crash2.id());
        }
    }
}
