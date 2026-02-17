use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use platform_challenge_sdk_wasm::CommandRequest;

#[allow(dead_code)]
pub struct TermTask {
    pub id: String,
    pub name: String,
    pub difficulty: Difficulty,
    pub test_script: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Copy)]
pub enum Difficulty {
    Easy,
    Medium,
    Hard,
}

pub fn default_tasks() -> Vec<TermTask> {
    vec![
        TermTask {
            id: String::from("hello-world"),
            name: String::from("Hello World"),
            difficulty: Difficulty::Easy,
            test_script: String::from(
                "#!/bin/bash\nset -e\nif [ ! -f hello.txt ]; then echo 'FAIL'; exit 1; fi\ncontent=$(cat hello.txt)\nif [[ \"$content\" == *\"Hello, world!\"* ]] || [[ \"$content\" == *\"Hello World\"* ]]; then echo 'PASS'; exit 0; else echo 'FAIL'; exit 1; fi",
            ),
            timeout_ms: 60_000,
        },
        TermTask {
            id: String::from("list-files"),
            name: String::from("List Files"),
            difficulty: Difficulty::Easy,
            test_script: String::from(
                "#!/bin/bash\nset -e\nif [ ! -f files.txt ]; then echo 'FAIL'; exit 1; fi\necho 'PASS'; exit 0",
            ),
            timeout_ms: 60_000,
        },
        TermTask {
            id: String::from("find-pattern"),
            name: String::from("Find Pattern"),
            difficulty: Difficulty::Medium,
            test_script: String::from(
                "#!/bin/bash\nset -e\nif [ ! -f result.txt ]; then echo 'FAIL'; exit 1; fi\necho 'PASS'; exit 0",
            ),
            timeout_ms: 120_000,
        },
        TermTask {
            id: String::from("process-csv"),
            name: String::from("Process CSV"),
            difficulty: Difficulty::Medium,
            test_script: String::from(
                "#!/bin/bash\nset -e\nif [ ! -f output.csv ]; then echo 'FAIL'; exit 1; fi\necho 'PASS'; exit 0",
            ),
            timeout_ms: 120_000,
        },
        TermTask {
            id: String::from("system-info"),
            name: String::from("System Info Script"),
            difficulty: Difficulty::Hard,
            test_script: String::from(
                "#!/bin/bash\nset -e\nif [ ! -f sysinfo.sh ]; then echo 'FAIL'; exit 1; fi\nchmod +x sysinfo.sh && ./sysinfo.sh > /dev/null 2>&1 && echo 'PASS' && exit 0 || (echo 'FAIL'; exit 1)",
            ),
            timeout_ms: 180_000,
        },
    ]
}

pub fn build_test_command(task: &TermTask) -> CommandRequest {
    CommandRequest {
        command: String::from("bash"),
        args: vec![String::from("-c"), task.test_script.clone()],
        env_vars: Vec::new(),
        working_dir: Some(String::from("/app")),
        timeout_ms: task.timeout_ms,
    }
}
