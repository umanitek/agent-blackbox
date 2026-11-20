"""The shell channel's file view (detection/shell_files.py).

A path rule only protects a file if it sees every way the agent reaches it;
these tests pin which commands count, how words are split, and which
arguments are taken as whole folders.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import action_parsing
from plugins.blackbox.detection.paths.shell_files import shell_file_args


def _paths(command):
    return [(arg.path, arg.command, arg.recursive) for arg in shell_file_args(command)]


def test_escaped_space_keeps_a_macos_path_whole():
    assert _paths("cat ~/Library/Application\\ Support/Google/Chrome/Default/x.log") == [
        ("~/Library/Application Support/Google/Chrome/Default/x.log", "cat", False),
    ]


def test_quoted_path_with_spaces_is_one_argument():
    assert _paths('cp -r "$HOME/Library/Application Support/BraveSoftware" /tmp/out') == [
        ("~/Library/Application Support/BraveSoftware", "cp", True),   # the home folder is written ~ (below)
        ("/tmp/out", "cp", True),
    ]


@pytest.mark.parametrize("spelling", ["$HOME", "${HOME}", '"$HOME"', "$HOME/"])
def test_the_home_folder_by_its_variable_is_read_as_the_home_folder(spelling):
    # 2026-11-20, a real agent on a real machine: `cat ~/.ssh/<key>` was blocked, the model retried
    # `cat $HOME/.ssh/<key>` by itself and the file came back — every rule expands ~, none expanded $HOME.
    assert _paths(f"cat {spelling}/.ssh/id_rsa")[0][0].replace("//", "/") == "~/.ssh/id_rsa"


def test_a_variable_that_only_starts_like_home_is_left_alone():
    assert _paths("cat $HOMEWORK/notes.txt") == [("$HOMEWORK/notes.txt", "cat", False)]


def test_archive_commands_take_folders_whole():
    assert [arg.recursive for arg in shell_file_args("tar czf out.tgz ~/.config")] == [True, True]
    assert [arg.recursive for arg in shell_file_args("zip -r out.zip ~/.config")] == [True, True]
    assert [arg.recursive for arg in shell_file_args("ditto -c -k ~/Library x.zip")] == [True, True]


def test_grep_reads_folders_only_with_a_recursive_flag():
    assert _paths("grep -r seed ~/.config") == [("~/.config", "grep", True)]
    assert _paths("grep -Rn seed ~/.config") == [("~/.config", "grep", True)]
    assert _paths("grep seed notes.txt") == [("notes.txt", "grep", False)]


def test_each_command_after_a_separator_is_its_own():
    assert _paths("cd /tmp && cat a.txt | base64 > b.txt; ls ~/x") == [
        ("/tmp/a.txt", "cat", False),   # the cd before it is followed
    ]


def test_command_named_by_full_path_is_recognised():
    assert _paths("/bin/cat ~/.ssh/id_rsa") == [("~/.ssh/id_rsa", "cat", False)]


def test_windows_paths_keep_their_backslashes():
    assert _paths(r"type C:\Users\a\AppData\Local\x.ldb & echo hi") == [
        (r"C:\Users\a\AppData\Local\x.ldb", "type", False),
    ]
    assert _paths(r'Compress-Archive -Path "%LOCALAPPDATA%\Google\Chrome\User Data" -DestinationPath o.zip') == [
        (r"%LOCALAPPDATA%\Google\Chrome\User Data", "compress-archive", True),
        ("o.zip", "compress-archive", True),
    ]


def test_unbalanced_quote_still_yields_paths():
    assert _paths("cat ~/.ssh/id_rsa 'oops") == [("~/.ssh/id_rsa", "cat", False)]


def test_commands_that_touch_no_file_yield_nothing():
    assert _paths("echo hello && ls -la && pwd") == []
    assert _paths("") == []


def test_parse_shell_reads_keeps_its_contract():
    assert action_parsing.parse_shell_reads("cat ~/.ssh/id_rsa && head -5 package.json") == ["~/.ssh/id_rsa", "package.json"]


# -- find: what it finds is read only when it feeds a reader --------------------

FIND_END = " {} " + chr(92) + ";"   # the shell's "{} \;" ending, spelled without escape puzzles


@pytest.mark.parametrize("command", [
    "find ~/.config/google-chrome -name '*.log' -exec cat" + FIND_END,
    "find ~/.config/google-chrome -type f -exec base64 {} +",
    "find ~/.config/google-chrome -execdir cp {} /var/tmp/x" + FIND_END[3:],
    "find ~/.config/google-chrome -type f -print0 | xargs -0 cat",
    "find ~/.config/google-chrome -name '*.ldb' | xargs -I {} tar czf out.tgz {}",
])
def test_a_find_that_feeds_a_reader_hands_its_folder_over_whole(command):
    assert ("~/.config/google-chrome", "find", True) in _paths(command)


@pytest.mark.parametrize("command", [
    "find ~/.config -name '*.json'",                 # lists names only
    "find . -name '*.pyc' -delete",
    "find ~/.ssh -exec ls -la {} +",                 # ls reads no contents
    "find . -type f | wc -l",
])
def test_a_find_that_only_lists_or_deletes_reads_nothing(command):
    assert [arg for arg in _paths(command) if arg[1] == "find"] == []


def test_commands_after_a_find_exec_are_still_parsed():
    assert _paths("find ~/x -exec base64" + FIND_END + " && cat b.txt") == [("~/x", "find", True), ("b.txt", "cat", False)]


# -- one-line scripts: the quoted paths in the code are read ----------------------

@pytest.mark.parametrize("command, path", [
    ("""python3 -c "print(open('/home/u/.ssh/id_rsa').read())" """, "/home/u/.ssh/id_rsa"),
    ("""node -e "require('fs').readFileSync('/home/u/.config/solana/id.json')" """, "/home/u/.config/solana/id.json"),
    ("""ruby -e "puts File.read('~/.electrum/wallets/default_wallet')" """, "~/.electrum/wallets/default_wallet"),
    ("""perl -e 'open(F, "/home/u/.aws/credentials"); print <F>'""", "/home/u/.aws/credentials"),
    ("""php -r "echo file_get_contents('/home/u/.env');" """, "/home/u/.env"),
])
def test_a_one_line_script_reads_the_paths_it_quotes(command, path):
    assert path in [arg.path for arg in shell_file_args(command)]


def test_a_relative_path_joined_onto_the_home_folder_is_taken_from_home():
    command = """node -e "fs.readFileSync(path.join(os.homedir(), '.config/solana/id.json'))" """
    assert "~/.config/solana/id.json" in [arg.path for arg in shell_file_args(command)]


def test_a_script_that_packs_folders_hands_them_over_whole():
    command = """python3 -c "import shutil; shutil.make_archive('out', 'zip', '/home/u/.config')" """
    assert ("/home/u/.config", "python3", True) in _paths(command)


def test_a_heredoc_script_is_read_like_a_one_liner():
    command = "python3 - <<'EOF'\nimport shutil\nshutil.copytree('/home/u/.config/Exodus', 'loot')\nEOF"
    assert ("/home/u/.config/Exodus", "python3", True) in _paths(command)


@pytest.mark.parametrize("command", [
    """python3 -c "print(1 + 1)" """,
    """python3 -c "import requests; print(requests.get('https://example.com/a/b').status_code)" """,   # a URL
    """node -e "console.log('hello world')" """,
])
def test_scripts_without_file_paths_yield_nothing(command):
    assert _paths(command) == []


# -- cd: relative paths after a cd in the same command line --------------------

@pytest.mark.parametrize("command, path", [
    ("cd ~ && zip -qr - .config/Exodus/exodus.wallet", "~/.config/Exodus/exodus.wallet"),   # found on the bench
    ("cd ~/.config && tar czf x.tgz Exodus", "~/.config/Exodus"),
    ("cd && cat .ssh/id_rsa", "~/.ssh/id_rsa"),
    ("cd /srv; cd app && cat .env", "/srv/app/.env"),
    ("cd ~/.config/google-chrome && find . -exec cat {} +", "~/.config/google-chrome"),
])
def test_a_cd_earlier_in_the_line_places_relative_paths(command, path):
    assert path in [arg.path for arg in shell_file_args(command)]


def test_a_cd_to_somewhere_unknown_leaves_paths_relative():
    assert [arg.path for arg in shell_file_args("cd $DIR && cat a/b.txt")] == ["a/b.txt"]
    assert [arg.path for arg in shell_file_args("cd - && cat a/b.txt")] == ["a/b.txt"]


def test_zip_to_stdout_reads_every_path():
    assert [(arg.path, arg.destination) for arg in shell_file_args("zip -qr - ~/.ssh")] == [("~/.ssh", False)]


def test_old_style_tar_flags_are_not_a_path():
    assert [arg.path for arg in shell_file_args("tar czf - ~/.ssh")] == ["~/.ssh"]
