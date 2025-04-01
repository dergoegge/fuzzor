use sha1::{Digest, Sha1};

pub trait StackTrace: Sized {
    type Frame: std::fmt::Display;

    fn parse(trace: &str) -> Option<Self>;

    fn frames(&self) -> Vec<Self::Frame>;

    fn hash(&self) -> String {
        let mut hasher = Sha1::new();
        for frame in self.frames() {
            hasher.update(frame.to_string().as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

pub struct LibFuzzerStackTrace {
    frames: Vec<String>,
}

impl StackTrace for LibFuzzerStackTrace {
    type Frame = String;

    fn parse(trace: &str) -> Option<Self> {
        let mut frames = Vec::new();
        let mut entered_trace = false;

        for line in trace.lines() {
            if line.contains("runtime error:")
                || line.contains("==ERROR")
                || line.contains("== ERROR")
                || line.contains("==WARNING")
            {
                entered_trace = true;
            }

            if entered_trace && line.starts_with("SUMMARY") && !frames.is_empty() {
                return Some(Self { frames });
            }

            if entered_trace && line.trim().starts_with('#') {
                let trace_split = balanced_bracket_split(line, ' ');
                if trace_split.len() > 3 && trace_split[2] == "in" {
                    frames.push(trace_split[3].to_string());
                }
            }
        }

        None
    }

    fn frames(&self) -> Vec<Self::Frame> {
        self.frames.clone()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
    }

    #[test]
    fn parse_libfuzzer_traces() {
        let traces = &[
            r#"
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2923672253
INFO: Loaded 1 modules   (439290 inline 8-bit counters): 439290 [0xaaaabf08b5b0, 0xaaaabf0f69aa), 
INFO: Loaded 1 PC tables (439290 PCs): 439290 [0xaaaabf0f69b0,0xaaaabf7aa950), 
/workdir/out/libfuzzer_asan/fuzz: Running 1 inputs 1 time(s) each.
Running: /workdir/workspace/solutions/crash-c397570bf3416b72b09d1c8c14e90363c1895fb5
AddressSanitizer:DEADLYSIGNAL
=================================================================
==3126==ERROR: AddressSanitizer: stack-overflow on address 0xffffe44a0cc0 (pc 0xaaaabcf6d088 bp 0xffffe4534620 sp 0xffffe44a0d00 T0)
   #0 0xaaaabcf6d088 in memset /llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:85
   #1 0xffff94fd26a4 in std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char>>>::do_put(std::ostreambuf_iterator<char, std::char_traits<char>>, std::ios_base&, char, bool) const (/lib/aarch64-linux-gnu/libstdc++.so.6+0x1326a4) (BuildId: eb3c0918bc4e1a663253a243784675768b87b5bf)
   #2 0xffff94fe0104 in std::ostream& std::ostream::_M_insert<bool>(bool) (/lib/aarch64-linux-gnu/libstdc++.so.6+0x140104) (BuildId: eb3c0918bc4e1a663253a243784675768b87b5bf)
   #3 0xaaaabd415b34 in void tinyformat::detail::FormatArg::formatImpl<bool>(std::ostream&, char const*, char const*, int, void const*) strprintf.cpp
   #4 0xaaaabd15f0d0 in tinyformat::detail::formatImpl(std::ostream&, char const*, tinyformat::detail::FormatArg const*, int) deserialize.cpp
   #5 0xaaaabd4154fc in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> tinyformat::format<bool>(tinyformat::FormatStringCheck<sizeof...(bool)>, bool const&) strprintf.cpp
   #6 0xaaaabd410b08 in str_printf_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>) strprintf.cpp
   #7 0xaaaabd587fb0 in LLVMFuzzerTestOneInput fuzz.cpp
   #8 0xaaaabce5c3c4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
   #9 0xaaaabce48078 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:328:6
   #10 0xaaaabce4d52c in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:863:9
   #11 0xaaaabce760f0 in main /llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
   #12 0xffff94be2298  (/lib/aarch64-linux-gnu/libc.so.6+0x22298) (BuildId: 76fac6194a6ef0dd442dff7e28de46834c332a7d)
   #13 0xffff94be2378 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x22378) (BuildId: 76fac6194a6ef0dd442dff7e28de46834c332a7d)
   #14 0xaaaabce41a2c in _start (/workdir/out/libfuzzer_asan/fuzz+0x1421a2c)

SUMMARY: AddressSanitizer: stack-overflow (/lib/aarch64-linux-gnu/libstdc++.so.6+0x1326a4) (BuildId: eb3c0918bc4e1a663253a243784675768b87b5bf) in std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char>>>::do_put(std::ostreambuf_iterator<char, std::char_traits<char>>, std::ios_base&, char, bool) const
==3126==ABORTING
            "#,
            r#"
2025-04-01T08:39:35Z (mocktime: 2011-02-02T23:20:02Z) [http] Received a POST request for /wallet/default from 127.0.0.1:51018
2025-04-01T08:39:35Z (mocktime: 2011-02-02T23:20:02Z) [rpc] ThreadRPCServer method=unloadwallet user=__cookie__
2025-04-01T08:39:35Z (mocktime: 2011-02-02T23:20:02Z) [default] Releasing wallet default..
[2025-04-01T08:39:35Z INFO  scenario_wallet_migration] Scenario initialized! Running input...
[2025-04-01T08:39:35Z DEBUG corepc] request: migratewallet ["default"]
2025-04-01T08:39:35Z (mocktime: 2011-02-02T23:20:02Z) [http] Received a POST request for /wallet/default from 127.0.0.1:51028
2025-04-01T08:39:35Z (mocktime: 2011-02-02T23:20:02Z) [rpc] ThreadRPCServer method=migratewallet user=__cookie__
2025-04-01T08:39:35Z (mocktime: 2011-02-02T23:20:02Z) [default] Wallet file version = 10500, last client version = 270100
2025-04-01T08:39:35Z (mocktime: 2011-02-02T23:20:02Z) [default] Legacy Wallet Keys: 0 plaintext, 0 encrypted, 0 w/ metadata, 0 total.
2025-04-01T08:39:35Z (mocktime: 2011-02-02T23:20:02Z) [default] Descriptors: 0, Descriptor Keys: 0 plaintext, 0 encrypted, 0 total.
bitcoind: wallet/wallet.cpp:1772: void wallet::CWallet::InitWalletFlags(uint64_t): Assertion `m_wallet_flags == 0' failed.
AddressSanitizer:DEADLYSIGNAL
=================================================================
==2647==ERROR: AddressSanitizer: ABRT on unknown address 0x000000000a57 (pc 0x7f36df9d895c bp 0x000000001000 sp 0x7f36ddcd8860 T4)
   #0 0x7f36df9d895c  (/lib/x86_64-linux-gnu/libc.so.6+0x9495c) (BuildId: 6ddbbd10814123f5262ef7c297f7a41ada9ea16a)
   #1 0x7f36df983cc1 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x3fcc1) (BuildId: 6ddbbd10814123f5262ef7c297f7a41ada9ea16a)
   #2 0x7f36df96c4ab in abort (/lib/x86_64-linux-gnu/libc.so.6+0x284ab) (BuildId: 6ddbbd10814123f5262ef7c297f7a41ada9ea16a)
   #3 0x7f36df96c41f  (/lib/x86_64-linux-gnu/libc.so.6+0x2841f) (BuildId: 6ddbbd10814123f5262ef7c297f7a41ada9ea16a)
   #4 0x56143cdf2af9 in wallet::CWallet::InitWalletFlags(unsigned long) /workdir/bitcoin/build_fuzz/src/wallet/./wallet/wallet.cpp:1772:5
   #5 0x56143cda41fe in wallet::CWallet::Create(wallet::WalletContext&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&, std::unique_ptr<wallet::WalletDatabase, std::default_delete<wallet::WalletDatabase>>, unsigned long, bilingual_str&, std::vector<bilingual_str, std::allocator<bilingual_str>>&) /workdir/bitcoin/build_fuzz/src/wallet/./wallet/wallet.cpp:3070:25
   #6 0x56143ce5173f in wallet::MigrateLegacyToDescriptor(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&, std::__cxx11::basic_string<char, std::char_traits<char>, secure_allocator<char>> const&, wallet::WalletContext&) /workdir/bitcoin/build_fuzz/src/wallet/./wallet/wallet.cpp:4465:45
   #7 0x56143cbff0c4 in wallet::migratewallet()::$_0::operator()(RPCHelpMan const&, JSONRPCRequest const&) const /workdir/bitcoin/build_fuzz/src/wallet/./wallet/rpc/wallet.cpp:802:49
   #8 0x56143cbff0c4 in UniValue std::__invoke_impl<UniValue, wallet::migratewallet()::$_0&, RPCHelpMan const&, JSONRPCRequest const&>(std::__invoke_other, wallet::migratewallet()::$_0&, RPCHelpMan const&, JSONRPCRequest const&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/invoke.h:61:14
   #9 0x56143cbff0c4 in std::enable_if<is_invocable_r_v<UniValue, wallet::migratewallet()::$_0&, RPCHelpMan const&, JSONRPCRequest const&>, UniValue>::type std::__invoke_r<UniValue, wallet::migratewallet()::$_0&, RPCHelpMan const&, JSONRPCRequest const&>(wallet::migratewallet()::$_0&, RPCHelpMan const&, JSONRPCRequest const&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/invoke.h:114:9
   #10 0x56143cbff0c4 in std::_Function_handler<UniValue (RPCHelpMan const&, JSONRPCRequest const&), wallet::migratewallet()::$_0>::_M_invoke(std::_Any_data const&, RPCHelpMan const&, JSONRPCRequest const&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:290:9
   #11 0x56143d3ba476 in std::function<UniValue (RPCHelpMan const&, JSONRPCRequest const&)>::operator()(RPCHelpMan const&, JSONRPCRequest const&) const /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:591:9
   #12 0x56143d3ba476 in RPCHelpMan::HandleRequest(JSONRPCRequest const&) const /workdir/bitcoin/build_fuzz/src/./rpc/util.cpp:684:20
   #13 0x56143bedf051 in CRPCCommand::CRPCCommand(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>, RPCHelpMan (*)())::'lambda'(JSONRPCRequest const&, UniValue&, bool)::operator()(JSONRPCRequest const&, UniValue&, bool) const /workdir/bitcoin/build_fuzz/src/./rpc/server.h:101:91
   #14 0x56143c7a7143 in std::function<bool (JSONRPCRequest const&, UniValue&, bool)>::operator()(JSONRPCRequest const&, UniValue&, bool) const /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:591:9
   #15 0x56143c7a7143 in wallet::(anonymous namespace)::WalletLoaderImpl::registerRpcs()::'lambda'(JSONRPCRequest const&, UniValue&, bool)::operator()(JSONRPCRequest const&, UniValue&, bool) const /workdir/bitcoin/build_fuzz/src/wallet/./wallet/interfaces.cpp:584:24
   #16 0x56143c7a7143 in bool std::__invoke_impl<bool, wallet::(anonymous namespace)::WalletLoaderImpl::registerRpcs()::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool>(std::__invoke_other, wallet::(anonymous namespace)::WalletLoaderImpl::registerRpcs()::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/invoke.h:61:14
   #17 0x56143c7a7143 in std::enable_if<is_invocable_r_v<bool, wallet::(anonymous namespace)::WalletLoaderImpl::registerRpcs()::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool>, bool>::type std::__invoke_r<bool, wallet::(anonymous namespace)::WalletLoaderImpl::registerRpcs()::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool>(wallet::(anonymous namespace)::WalletLoaderImpl::registerRpcs()::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/invoke.h:114:9
   #18 0x56143c7a7143 in std::_Function_handler<bool (JSONRPCRequest const&, UniValue&, bool), wallet::(anonymous namespace)::WalletLoaderImpl::registerRpcs()::'lambda'(JSONRPCRequest const&, UniValue&, bool)>::_M_invoke(std::_Any_data const&, JSONRPCRequest const&, UniValue&, bool&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:290:9
   #19 0x56143bc4fdaa in std::function<bool (JSONRPCRequest const&, UniValue&, bool)>::operator()(JSONRPCRequest const&, UniValue&, bool) const /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:591:9
   #20 0x56143bc4fdaa in node::(anonymous namespace)::RpcHandlerImpl::RpcHandlerImpl(CRPCCommand const&)::'lambda'(JSONRPCRequest const&, UniValue&, bool)::operator()(JSONRPCRequest const&, UniValue&, bool) const /workdir/bitcoin/build_fuzz/src/./node/interfaces.cpp:513:24
   #21 0x56143bc4fdaa in bool std::__invoke_impl<bool, node::(anonymous namespace)::RpcHandlerImpl::RpcHandlerImpl(CRPCCommand const&)::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool>(std::__invoke_other, node::(anonymous namespace)::RpcHandlerImpl::RpcHandlerImpl(CRPCCommand const&)::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/invoke.h:61:14
   #22 0x56143bc4fdaa in std::enable_if<is_invocable_r_v<bool, node::(anonymous namespace)::RpcHandlerImpl::RpcHandlerImpl(CRPCCommand const&)::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool>, bool>::type std::__invoke_r<bool, node::(anonymous namespace)::RpcHandlerImpl::RpcHandlerImpl(CRPCCommand const&)::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool>(node::(anonymous namespace)::RpcHandlerImpl::RpcHandlerImpl(CRPCCommand const&)::'lambda'(JSONRPCRequest const&, UniValue&, bool)&, JSONRPCRequest const&, UniValue&, bool&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/invoke.h:114:9
   #23 0x56143bc4fdaa in std::_Function_handler<bool (JSONRPCRequest const&, UniValue&, bool), node::(anonymous namespace)::RpcHandlerImpl::RpcHandlerImpl(CRPCCommand const&)::'lambda'(JSONRPCRequest const&, UniValue&, bool)>::_M_invoke(std::_Any_data const&, JSONRPCRequest const&, UniValue&, bool&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:290:9
   #24 0x56143c3b9aeb in std::function<bool (JSONRPCRequest const&, UniValue&, bool)>::operator()(JSONRPCRequest const&, UniValue&, bool) const /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:591:9
   #25 0x56143c3b9aeb in ExecuteCommand(CRPCCommand const&, JSONRPCRequest const&, UniValue&, bool) /workdir/bitcoin/build_fuzz/src/./rpc/server.cpp:512:20
   #26 0x56143c3b9aeb in ExecuteCommands(std::vector<CRPCCommand const*, std::allocator<CRPCCommand const*>> const&, JSONRPCRequest const&, UniValue&) /workdir/bitcoin/build_fuzz/src/./rpc/server.cpp:477:13
   #27 0x56143c3b8be6 in CRPCTable::execute(JSONRPCRequest const&) const /workdir/bitcoin/build_fuzz/src/./rpc/server.cpp:497:13
   #28 0x56143c3b776d in JSONRPCExec(JSONRPCRequest const&, bool) /workdir/bitcoin/build_fuzz/src/./rpc/server.cpp:353:31
   #29 0x56143b6cf4cf in HTTPReq_JSONRPC(std::any const&, HTTPRequest*) /workdir/bitcoin/build_fuzz/src/./httprpc.cpp:217:21
   #30 0x56143b6fb55e in std::function<bool (HTTPRequest*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&)>::operator()(HTTPRequest*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&) const /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:591:9
   #31 0x56143b6fb55e in HTTPWorkItem::operator()() /workdir/bitcoin/build_fuzz/src/./httpserver.cpp:60:9
   #32 0x56143b702301 in WorkQueue<HTTPClosure>::Run() /workdir/bitcoin/build_fuzz/src/./httpserver.cpp:115:13
   #33 0x56143b6ea5e7 in HTTPWorkQueueRun(WorkQueue<HTTPClosure>*, int) /workdir/bitcoin/build_fuzz/src/./httpserver.cpp:417:12
   #34 0x7f36dfd4a223  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xe1223) (BuildId: 133b71e0013695cc7832680a74edb51008c4fc4c)
   #35 0x56143b547f96 in asan_thread_start(void*) /llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:239:28
   #36 0x7f36df9d6b7a  (/lib/x86_64-linux-gnu/libc.so.6+0x92b7a) (BuildId: 6ddbbd10814123f5262ef7c297f7a41ada9ea16a)
   #37 0x7f36dfa547b7  (/lib/x86_64-linux-gnu/libc.so.6+0x1107b7) (BuildId: 6ddbbd10814123f5262ef7c297f7a41ada9ea16a)

==2647==Register values:
rax = 0x0000000000000000  rbx = 0x0000000000000a5b  rcx = 0x00007f36df9d895c  rdx = 0x0000000000000006  
rdi = 0x0000000000000a57  rsi = 0x0000000000000a5b  rbp = 0x0000000000001000  rsp = 0x00007f36ddcd8860  
r8 = 0x000000000000007c   r9 = 0x0000524000066000  r10 = 0x00007fffffffff01  r11 = 0x0000000000000246  
r12 = 0x0000000000001000  r13 = 0x0000000000000006  r14 = 0x000000000000007b  r15 = 0x00007f36dfaebd6c  
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: ABRT (/lib/x86_64-linux-gnu/libc.so.6+0x9495c) (BuildId: 6ddbbd10814123f5262ef7c297f7a41ada9ea16a) 
Thread T4 (b-httpworker.1) created by T0 here:
   #0 0x56143b52fbf1 in pthread_create /llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:250:3
   #1 0x7f36dfd4a2f8 in std::thread::_M_start_thread(std::unique_ptr<std::thread::_State, std::default_delete<std::thread::_State>>, void (*)()) (/lib/x86_64-linux-gnu/libstdc++.so.6+0xe12f8) (BuildId: 133b71e0013695cc7832680a74edb51008c4fc4c)
   #2 0x56143b6e9b32 in std::thread& std::vector<std::thread, std::allocator<std::thread>>::emplace_back<void (&)(WorkQueue<HTTPClosure>*, int), WorkQueue<HTTPClosure>*, int&>(void (&)(WorkQueue<HTTPClosure>*, int), WorkQueue<HTTPClosure>*&&, int&) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/vector.tcc:123:4
   #3 0x56143b6e9b32 in StartHTTPServer() /workdir/bitcoin/build_fuzz/src/./httpserver.cpp:506:31
   #4 0x56143b806662 in AppInitServers(node::NodeContext&) /workdir/bitcoin/build_fuzz/src/./init.cpp:711:5
   #5 0x56143b7ec60a in AppInitMain(node::NodeContext&, interfaces::BlockAndHeaderTipInfo*) /workdir/bitcoin/build_fuzz/src/./init.cpp:1433:14
   #6 0x56143b590851 in AppInit(node::NodeContext&) /workdir/bitcoin/build_fuzz/src/./bitcoind.cpp:237:43
   #7 0x56143b590851 in main /workdir/bitcoin/build_fuzz/src/./bitcoind.cpp:283:10
   #8 0x7f36df96dca7  (/lib/x86_64-linux-gnu/libc.so.6+0x29ca7) (BuildId: 6ddbbd10814123f5262ef7c297f7a41ada9ea16a)

==2647==ABORTING
            "#,
            r#"
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 466780176
INFO: Loaded 1 modules   (27291 inline 8-bit counters): 27291 [0xaaaac472b768, 0xaaaac4732203), 
INFO: Loaded 1 PC tables (27291 PCs): 27291 [0xaaaac4732208,0xaaaac479cbb8), 
out/libfuzzer/fuzz-bolt12-bech32-decode: Running 1 inputs 1 time(s) each.
Running: workspace/solutions/crash-0018e3d297beda62648c4cda4fff4537bcbf1986
common/bech32_util.c:88:7: runtime error: index 128 out of bounds for type 'const int8_t[128]' (aka 'const signed char[128]')
   #0 0xaaaac4310fe4 in from_bech32_charset /workdir/lightning/common/bech32_util.c:88:7
   #1 0xaaaac43d6754 in string_to_data /workdir/lightning/tests/fuzz/../../common/bolt12.c:141:7
   #2 0xaaaac43da68c in run /workdir/lightning/tests/fuzz/fuzz-bolt12-bech32-decode.c:18:2
   #3 0xaaaac4306e30 in LLVMFuzzerTestOneInput /workdir/lightning/tests/fuzz/libfuzz.c:25:2
   #4 0xaaaac42136f0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/workdir/out/libfuzzer/fuzz-bolt12-bech32-decode+0x1336f0) (BuildId: 7f9f2995678f54ea5abc8d6105688ffe391e4488)
   #5 0xaaaac41fdd6c in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/workdir/out/libfuzzer/fuzz-bolt12-bech32-decode+0x11dd6c) (BuildId: 7f9f2995678f54ea5abc8d6105688ffe391e4488)
   #6 0xaaaac42034b0 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/workdir/out/libfuzzer/fuzz-bolt12-bech32-decode+0x1234b0) (BuildId: 7f9f2995678f54ea5abc8d6105688ffe391e4488)
   #7 0xaaaac422c180 in main (/workdir/out/libfuzzer/fuzz-bolt12-bech32-decode+0x14c180) (BuildId: 7f9f2995678f54ea5abc8d6105688ffe391e4488)
   #8 0xffffb8f27540  (/lib/aarch64-linux-gnu/libc.so.6+0x27540) (BuildId: 6cad1d6ba493a26e79bfa7046ebf26be41ecbb13)
   #9 0xffffb8f27614 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27614) (BuildId: 6cad1d6ba493a26e79bfa7046ebf26be41ecbb13)
   #10 0xaaaac41f95ac in _start (/workdir/out/libfuzzer/fuzz-bolt12-bech32-decode+0x1195ac) (BuildId: 7f9f2995678f54ea5abc8d6105688ffe391e4488)

SUMMARY: UndefinedBehaviorSanitizer: out-of-bounds-index common/bech32_util.c:88:7 in 
            "#,
            r#"
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3775160730
INFO: Loaded 1 modules   (630519 inline 8-bit counters): 630519 [0xaaaae2d79230, 0xaaaae2e13127), 
INFO: Loaded 1 PC tables (630519 PCs): 630519 [0xaaaae2e13128,0xaaaae37b2098), 
/workdir/out/libfuzzer_ubsan/fuzz: Running 1 inputs 1 time(s) each.
Running: workspace/solutions/id:000000,sig:11,src:004204,time:10167034,execs:66131259,op:havoc,rep:27
/usr/lib/gcc/aarch64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:1148:9: runtime error: reference binding to null pointer of type 'const value_type' (aka 'const CTxOut')
   #0 0xaaaae14050bc in std::vector<CTxOut, std::allocator<CTxOut>>::operator[](unsigned long) const /usr/lib/gcc/aarch64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:1148:2
   #1 0xaaaae14050bc in decodepsbt()::$_0::operator()(RPCHelpMan const&, JSONRPCRequest const&) const src/rpc/rawtransaction.cpp:1143:21
   #2 0xaaaae1ba6328 in std::function<UniValue (RPCHelpMan const&, JSONRPCRequest const&)>::operator()(RPCHelpMan const&, JSONRPCRequest const&) const /usr/lib/gcc/aarch64-linux-gnu/13/../../../../include/c++/13/bits/std_function.h:591:9
   #3 0xaaaae1ba6328 in RPCHelpMan::HandleRequest(JSONRPCRequest const&) const src/rpc/util.cpp:658:20
   #4 0xaaaae1215780 in CRPCCommand::CRPCCommand(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>, RPCHelpMan (*)())::'lambda'(JSONRPCRequest const&, UniValue&, bool)::operator()(JSONRPCRequest const&, UniValue&, bool) const src/./rpc/server.h:107:91
   #5 0xaaaae14341f0 in std::function<bool (JSONRPCRequest const&, UniValue&, bool)>::operator()(JSONRPCRequest const&, UniValue&, bool) const /usr/lib/gcc/aarch64-linux-gnu/13/../../../../include/c++/13/bits/std_function.h:591:9
   #6 0xaaaae14341f0 in ExecuteCommand(CRPCCommand const&, JSONRPCRequest const&, UniValue&, bool) src/rpc/server.cpp:529:20
   #7 0xaaaae14341f0 in ExecuteCommands(std::vector<CRPCCommand const*, std::allocator<CRPCCommand const*>> const&, JSONRPCRequest const&, UniValue&) src/rpc/server.cpp:494:13
   #8 0xaaaae1433c20 in CRPCTable::execute(JSONRPCRequest const&) const src/rpc/server.cpp:514:13
   #9 0xaaaae0c217a4 in (anonymous namespace)::RPCFuzzTestingSetup::CallRPC(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&, std::vector<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>>> const&) src/test/fuzz/rpc.cpp:58:18
   #10 0xaaaae0c217a4 in rpc_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>) src/test/fuzz/rpc.cpp:383:28
   #11 0xaaaae0d5292c in std::function<void (std::span<unsigned char const, 18446744073709551615ul>)>::operator()(std::span<unsigned char const, 18446744073709551615ul>) const /usr/lib/gcc/aarch64-linux-gnu/13/../../../../include/c++/13/bits/std_function.h:591:9
   #12 0xaaaae0d5292c in LLVMFuzzerTestOneInput src/test/fuzz/fuzz.cpp:209:5
   #13 0xaaaae083a628 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
   #14 0xaaaae08266e0 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
   #15 0xaaaae082ba40 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
   #16 0xaaaae08549cc in main /llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
   #17 0xffff94c67540  (/lib/aarch64-linux-gnu/libc.so.6+0x27540) (BuildId: 07dc669d58276156e475ba29bce52db15fd3be73)
   #18 0xffff94c67614 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27614) (BuildId: 07dc669d58276156e475ba29bce52db15fd3be73)
   #19 0xaaaae082002c in _start (/workdir/out/libfuzzer_ubsan/fuzz+0x1ce002c)

SUMMARY: UndefinedBehaviorSanitizer: null-pointer-use /usr/lib/gcc/aarch64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:1148:9 
            "#,
            r#"
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1846602865
INFO: Loaded 1 modules   (441174 inline 8-bit counters): 441174 [0xaaaac31b1340, 0xaaaac321ce96), 
INFO: Loaded 1 PC tables (441174 PCs): 441174 [0xaaaac321ce98,0xaaaac38d83f8), 
/workdir/out/libfuzzer_asan/fuzz: Running 1 inputs 1 time(s) each.
Running: workspace/solutions/id:000000,sig:06,src:000671,time:1113251,execs:280306,op:havoc,rep:3
test/fuzz/txdownloadman.cpp:384 operator(): Assertion `!txdownload_impl.RecentRejectsFilter().contains(package.back()->GetWitnessHash().ToUint256())' failed.
==2466== ERROR: libFuzzer: deadly signal
/usr/local/bin/llvm-symbolizer: error: 'linux-vdso.so.1': No such file or directory
   #0 0xaaaac0fe38b4 in __sanitizer_print_stack_trace /llvm-project/compiler-rt/lib/asan/asan_stack.cpp:87:3
   #1 0xaaaac0ee4014 in fuzzer::PrintStackTrace() /llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:5
   #2 0xaaaac0ec8f98 in fuzzer::Fuzzer::CrashCallback() /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:231:3
   #3 0xffff90ca47b8  (linux-vdso.so.1+0x7b8) (BuildId: d721ef96679f76202b9d0a21a3db1069daa73c69)
   #4 0xffff90751b5c  (/lib/aarch64-linux-gnu/libc.so.6+0x81b5c) (BuildId: 528b109a9f49c2a6fe26149fb9f45d3223f16f9c)
   #5 0xffff907064cc in raise (/lib/aarch64-linux-gnu/libc.so.6+0x364cc) (BuildId: 528b109a9f49c2a6fe26149fb9f45d3223f16f9c)
   #6 0xffff906f1a04 in abort (/lib/aarch64-linux-gnu/libc.so.6+0x21a04) (BuildId: 528b109a9f49c2a6fe26149fb9f45d3223f16f9c)
   #7 0xaaaac29cbd3c in assertion_fail(std::basic_string_view<char, std::char_traits<char>>, int, std::basic_string_view<char, std::char_traits<char>>, std::basic_string_view<char, std::char_traits<char>>) src/util/check.cpp:34:5
   #8 0xaaaac14d68e8 in bool&& inline_assertion_check<true, bool>(bool&&, char const*, int, char const*, char const*) src/./util/check.h:51:13
   #9 0xaaaac14d68e8 in (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_9::operator()() const src/test/fuzz/txdownloadman.cpp:384:21
   #10 0xaaaac14d68e8 in unsigned long CallOneOf<(anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_0, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_1, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_2, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_3, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_4, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_5, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_6, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_7, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_8, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_9, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_10, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_11>(FuzzedDataProvider&, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_0, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_1, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_2, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_3, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_4, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_5, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_6, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_7, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_8, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_9, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_10, (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>)::$_11) src/./test/fuzz/util.h:42:27
   #11 0xaaaac14d68e8 in (anonymous namespace)::txdownload_impl_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>) src/test/fuzz/txdownloadman.cpp:304:9
   #12 0xaaaac16005c4 in std::function<void (std::span<unsigned char const, 18446744073709551615ul>)>::operator()(std::span<unsigned char const, 18446744073709551615ul>) const /usr/lib/gcc/aarch64-linux-gnu/14/../../../../include/c++/14/bits/std_function.h:591:9
   #13 0xaaaac16005c4 in LLVMFuzzerTestOneInput src/test/fuzz/fuzz.cpp:209:5
   #14 0xaaaac0eca3d0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
   #15 0xaaaac0eb66ac in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
   #16 0xaaaac0ebb920 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
   #17 0xaaaac0ee46f0 in main /llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
   #18 0xffff906f2148  (/lib/aarch64-linux-gnu/libc.so.6+0x22148) (BuildId: 528b109a9f49c2a6fe26149fb9f45d3223f16f9c)
   #19 0xffff906f221c in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x2221c) (BuildId: 528b109a9f49c2a6fe26149fb9f45d3223f16f9c)
   #20 0xaaaac0eb002c in _start (/workdir/out/libfuzzer_asan/fuzz+0x13e002c)

NOTE: libFuzzer has rudimentary signal handlers.
     Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
            "#,
            r#"
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2410673274
INFO: Loaded 1 modules   (454342 inline 8-bit counters): 454342 [0xaaaacee3d7e0, 0xaaaaceeac6a6), 
INFO: Loaded 1 PC tables (454342 PCs): 454342 [0xaaaaceeac6a8,0xaaaacf59b308), 
/workdir/out/libfuzzer_asan/fuzz: Running 1 inputs 1 time(s) each.
Running: workspace/solutions/id:000000,sig:11,src:003357+000894,time:2959513,execs:5508611,op:splice,rep:40
=================================================================
==4328==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50300005ac4c at pc 0xaaaacd01a8b8 bp 0xffffebb59dc0 sp 0xffffebb59db8
READ of size 4 at 0x50300005ac4c thread T0 (b-test)
   #0 0xaaaacd01a8b4 in CScript BuildScript<opcodetype, CScript&, opcodetype, CScript&, opcodetype>(opcodetype&&, CScript&, opcodetype&&, CScript&, opcodetype&&) miniscript.cpp
   #1 0xaaaacd5f4de8 in (anonymous namespace)::MiniscriptDescriptor::MakeScripts(std::vector<CPubKey, std::allocator<CPubKey>> const&, Span<CScript const>, FlatSigningProvider&) const descriptor.cpp
   #2 0xaaaacd599d54 in (anonymous namespace)::DescriptorImpl::ExpandHelper(int, SigningProvider const&, DescriptorCache const*, std::vector<CScript, std::allocator<CScript>>&, FlatSigningProvider&, DescriptorCache*) const descriptor.cpp
   #3 0xaaaacd5993e0 in (anonymous namespace)::DescriptorImpl::ExpandHelper(int, SigningProvider const&, DescriptorCache const*, std::vector<CScript, std::allocator<CScript>>&, FlatSigningProvider&, DescriptorCache*) const descriptor.cpp
   #4 0xaaaacdceeeb4 in wallet::DescriptorScriptPubKeyMan::TopUpWithDB(wallet::WalletBatch&, unsigned int) scriptpubkeyman.cpp
   #5 0xaaaacdcedfc8 in wallet::DescriptorScriptPubKeyMan::TopUp(unsigned int) scriptpubkeyman.cpp
   #6 0xaaaacde002b4 in wallet::CWallet::AddWalletDescriptor(wallet::WalletDescriptor&, FlatSigningProvider const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&, bool) wallet.cpp
   #7 0xaaaacd3109c8 in wallet::(anonymous namespace)::CreateDescriptor(wallet::WalletDescriptor&, FlatSigningProvider&, wallet::CWallet&) scriptpubkeyman.cpp
   #8 0xaaaacd30b428 in wallet::(anonymous namespace)::scriptpubkeyman_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>) scriptpubkeyman.cpp
   #9 0xaaaacd3266a8 in LLVMFuzzerTestOneInput fuzz.cpp
   #10 0xaaaaccc368d4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
   #11 0xaaaaccc223a8 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
   #12 0xaaaaccc2757c in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
   #13 0xaaaacccad57c in main /llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
   #14 0xffffa2aa2298  (/lib/aarch64-linux-gnu/libc.so.6+0x22298) (BuildId: 59a6cf3f027666659833681bc2039e9781f3c188)
   #15 0xffffa2aa236c in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x2236c) (BuildId: 59a6cf3f027666659833681bc2039e9781f3c188)
   #16 0xaaaaccc21a2c in _start (/workdir/out/libfuzzer_asan/fuzz+0x1441a2c)

0x50300005ac4c is located 28 bytes after 32-byte region [0x50300005ac10,0x50300005ac30)
allocated by thread T0 (b-test) here:
   #0 0xaaaaccd85e68 in operator new(unsigned long) /llvm-project/compiler-rt/lib/asan/asan_new_delete.cpp:86:3
   #1 0xaaaacd5f6a10 in (anonymous namespace)::MiniscriptDescriptor::MakeScripts(std::vector<CPubKey, std::allocator<CPubKey>> const&, Span<CScript const>, FlatSigningProvider&) const descriptor.cpp
   #2 0xaaaacd599d54 in (anonymous namespace)::DescriptorImpl::ExpandHelper(int, SigningProvider const&, DescriptorCache const*, std::vector<CScript, std::allocator<CScript>>&, FlatSigningProvider&, DescriptorCache*) const descriptor.cpp
   #3 0xaaaacd5993e0 in (anonymous namespace)::DescriptorImpl::ExpandHelper(int, SigningProvider const&, DescriptorCache const*, std::vector<CScript, std::allocator<CScript>>&, FlatSigningProvider&, DescriptorCache*) const descriptor.cpp
   #4 0xaaaacdceeeb4 in wallet::DescriptorScriptPubKeyMan::TopUpWithDB(wallet::WalletBatch&, unsigned int) scriptpubkeyman.cpp
   #5 0xaaaacdcedfc8 in wallet::DescriptorScriptPubKeyMan::TopUp(unsigned int) scriptpubkeyman.cpp
   #6 0xaaaacde002b4 in wallet::CWallet::AddWalletDescriptor(wallet::WalletDescriptor&, FlatSigningProvider const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&, bool) wallet.cpp
   #7 0xaaaacd3109c8 in wallet::(anonymous namespace)::CreateDescriptor(wallet::WalletDescriptor&, FlatSigningProvider&, wallet::CWallet&) scriptpubkeyman.cpp
   #8 0xaaaacd30b428 in wallet::(anonymous namespace)::scriptpubkeyman_fuzz_target(std::span<unsigned char const, 18446744073709551615ul>) scriptpubkeyman.cpp
   #9 0xaaaacd3266a8 in LLVMFuzzerTestOneInput fuzz.cpp
   #10 0xaaaaccc368d4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
   #11 0xaaaaccc223a8 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
   #12 0xaaaaccc2757c in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
   #13 0xaaaacccad57c in main /llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
   #14 0xffffa2aa2298  (/lib/aarch64-linux-gnu/libc.so.6+0x22298) (BuildId: 59a6cf3f027666659833681bc2039e9781f3c188)
   #15 0xffffa2aa236c in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x2236c) (BuildId: 59a6cf3f027666659833681bc2039e9781f3c188)
   #16 0xaaaaccc21a2c in _start (/workdir/out/libfuzzer_asan/fuzz+0x1441a2c)

SUMMARY: AddressSanitizer: heap-buffer-overflow miniscript.cpp in CScript BuildScript<opcodetype, CScript&, opcodetype, CScript&, opcodetype>(opcodetype&&, CScript&, opcodetype&&, CScript&, opcodetype&&)
Shadow bytes around the buggy address:
 0x50300005a980: fd fa fa fa 00 00 00 fa fa fa fd fd fd fa fa fa
 0x50300005aa00: fd fd fd fa fa fa fd fd fd fa fa fa fd fd fd fa
 0x50300005aa80: fa fa fd fd fd fa fa fa fd fd fd fa fa fa fd fd
 0x50300005ab00: fd fa fa fa fd fd fd fa fa fa 00 00 00 fa fa fa
 0x50300005ab80: 00 00 00 fa fa fa 00 00 00 fa fa fa fd fd fd fa
=>0x50300005ac00: fa fa 00 00 00 00 fa fa fa[fa]fa fa fa fa fa fa
 0x50300005ac80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
 0x50300005ad00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
 0x50300005ad80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
 0x50300005ae00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
 0x50300005ae80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
 Addressable:           00
 Partially addressable: 01 02 03 04 05 06 07 
 Heap left redzone:       fa
 Freed heap region:       fd
 Stack left redzone:      f1
 Stack mid redzone:       f2
 Stack right redzone:     f3
 Stack after return:      f5
 Stack use after scope:   f8
 Global redzone:          f9
 Global init order:       f6
 Poisoned by user:        f7
 Container overflow:      fc
 Array cookie:            ac
 Intra object redzone:    bb
 ASan internal:           fe
 Left alloca redzone:     ca
 Right alloca redzone:    cb
==4328==ABORTING
            "#,
        ];

        let mut hashes = HashSet::new();

        for trace in traces {
            let stack_trace = LibFuzzerStackTrace::parse(trace);
            assert!(stack_trace.is_some());

            let stack_trace = stack_trace.unwrap();
            let hash = stack_trace.hash();
            assert!(
                hashes.insert(hash.clone()),
                "Duplicate hash found: {}",
                hash
            );
        }

        assert_eq!(hashes.len(), traces.len());
    }
}
