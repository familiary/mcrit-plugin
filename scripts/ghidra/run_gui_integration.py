#!/usr/bin/env python3
"""Drive the MCRIT window in Ghidra's GUI against a live MCRIT server.

Starts Ghidra 12.0+ in PyGhidra mode with a throwaway user profile and project, so your own Ghidra
settings are not touched, imports and analyzes --input twice (the copy tests switching programs),
and then works through the plugin as a user would, asserting each step:

  the MCRIT.py script from mcrit_plugin/ghidra/ghidra_scripts opens the window; Convert asks for
  family and version of the unknown sample; Upload; a new matching job through the result dialog,
  then its result; live Function Scope and Block Scope queries; a remote CFG with the matched
  local blocks tinted; label fetch and import in the Function Overview; the Sample Match Summary;
  the YARA builder; Export;
  the placeholder for a program without a session; the upload prompt when closing a program.

The input's SHA-256 must be new to the server; pass the reference sample's SHA-256 to also assert
that it is matched. Needs a display: on a headless machine run it under xvfb-run. With
--screenshots DIR, ImageMagick's import saves a screenshot per step.

  xvfb-run -a python scripts/ghidra/run_gui_integration.py --input /tmp/mcrit-query \\
      --reference-sha256 <sha256> --mcrit-server http://127.0.0.1:8000/
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
PROJECT_NAME = "MCRITGUI"
COPY_NAME = "copy-of-input"
FAMILY = "mcrit-plugin-ci"
VERSION = "ghidra-gui-query"
RESULT = {"ok": False}


def _check(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS {message}", flush=True)


def _wait(predicate, message, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = predicate()
        except Exception:
            result = None
        if result:
            return result
        time.sleep(0.5)
    raise TimeoutError(f"timed out: {message}")


# preparation (separate process: a JVM is started once per process, headless here)


def prepare(input_path: Path, workdir: Path):
    import pyghidra

    pyghidra.start()
    (workdir / "project").mkdir(parents=True, exist_ok=True)
    project = pyghidra.open_project(str(workdir / "project"), PROJECT_NAME, create=True)
    try:
        for name in (input_path.name, COPY_NAME):
            loader = pyghidra.program_loader().project(project).source(str(input_path)).name(name)
            with loader.load() as results:
                results.save(pyghidra.task_monitor())
                path = results.getPrimaryDomainObject().getDomainFile().getPathname()
            with pyghidra.program_context(project, path) as program:
                pyghidra.analyze(program)
                program.save("analyzed", pyghidra.task_monitor())
            print(f"[prepare] imported and analyzed {path}", flush=True)
    finally:
        project.close()


# GUI helpers (run on the test thread, touching Swing through the event dispatch thread)


class Gui:
    def __init__(self, screenshots):
        self.screenshots = screenshots
        self.step = 0

    def edt(self, func):
        from mcrit_plugin.ghidra import swing

        return swing.invoke_and_wait(func)

    def later(self, func):
        from mcrit_plugin.ghidra import swing

        swing.invoke_later(func)

    def shot(self, name):
        if not self.screenshots or not shutil.which("import"):
            return
        self.step += 1
        target = Path(self.screenshots) / f"{self.step:02d}_{name}.png"
        subprocess.run(["import", "-window", "root", str(target)], check=False)

    def windows(self, title=None):
        from jpype import JClass

        windows = JClass("java.awt.Window").getWindows()
        return [
            window
            for window in windows
            if window.isShowing()
            and hasattr(window, "getTitle")
            and (title is None or str(window.getTitle()) == title)
        ]

    def window(self, title, timeout=60):
        return _wait(lambda: (self.windows(title) or [None])[0], f'window "{title}"', timeout)

    @staticmethod
    def find(component, class_suffix, text=None):
        found = []

        def walk(node):
            if node.getClass().getName().endswith(class_suffix) and (
                text is None or (hasattr(node, "getText") and str(node.getText()) == text)
            ):
                found.append(node)
            if hasattr(node, "getComponents"):
                for child in node.getComponents():
                    walk(child)

        walk(component)
        return found

    def press_tab(self, tabs):
        """Press the mouse on a visible, unselected tab header as a user does; returns its index.
        doClick-style shortcuts skip the event routing Ghidra's docking listeners take part in."""
        from java.awt import Toolkit
        from java.awt.event import InputEvent, MouseEvent
        from javax.swing import SwingUtilities

        def post():
            width = tabs.getWidth()
            for index in range(tabs.getTabCount()):
                rect = tabs.getBoundsAt(index)
                x, y = int(rect.getCenterX()), int(rect.getCenterY())
                if index != tabs.getSelectedIndex() and 0 <= x < width:
                    break
            else:
                raise AssertionError("no visible unselected tab")
            target = SwingUtilities.getDeepestComponentAt(tabs, x, y)
            point = SwingUtilities.convertPoint(tabs, x, y, target)
            queue = Toolkit.getDefaultToolkit().getSystemEventQueue()
            for kind, modifiers in (
                (MouseEvent.MOUSE_PRESSED, InputEvent.BUTTON1_DOWN_MASK),
                (MouseEvent.MOUSE_RELEASED, 0),
                (MouseEvent.MOUSE_CLICKED, 0),
            ):
                queue.postEvent(
                    MouseEvent(
                        target,
                        kind,
                        System.currentTimeMillis(),
                        modifiers,
                        int(point.getX()),
                        int(point.getY()),
                        1,
                        False,
                        MouseEvent.BUTTON1,
                    )
                )
            return index

        from java.lang import System

        return self.edt(post)

    def click(self, window, text):
        buttons = self.find(window, "JButton", text)
        _check(buttons, f'"{text}" button present')
        self.edt(lambda: buttons[0].doClick())


def run_steps(args, gui):
    from ghidra.framework.main import AppInfo
    from java.util import List
    from jpype import JClass

    project = _wait(AppInfo.getActiveProject, "Ghidra project", 180)
    data = project.getProjectData()
    domain_file = data.getFile("/" + args.input.name)
    tool = gui.edt(lambda: project.getToolServices().launchDefaultTool(List.of(domain_file)))
    program_manager = tool.getService(JClass("ghidra.app.services.ProgramManager"))
    program = _wait(program_manager.getCurrentProgram, "program in the CodeBrowser", 120)
    gui.edt(lambda: tool.getToolFrame().setBounds(0, 0, 1600, 1000))
    _check(program is not None, "CodeBrowser opened the input")

    # settings first: the session reads them when it is created
    options = tool.getOptions("MCRIT")

    def configure():
        from mcrit_plugin.ghidra.config import register_options

        register_options(tool)
        options.setString("MCRIT Server URL", args.mcrit_server)
        options.setBoolean("Submit Function Names on Close", True)

    gui.edt(configure)

    # open MCRIT the way a user does: the script from the plugin's ghidra_scripts directory
    resource_file = JClass("generic.jar.ResourceFile")
    script_util = JClass("ghidra.app.script.GhidraScriptUtil")
    scripts = str(REPO_ROOT / "mcrit_plugin" / "ghidra" / "ghidra_scripts")
    gui.edt(lambda: script_util.getBundleHost().add(resource_file(scripts), True, False))
    script_service = tool.getService(JClass("ghidra.app.services.GhidraScriptService"))
    gui.edt(script_service.refreshScriptList)
    info = script_util.newScriptInfo(script_util.findScriptByName("MCRIT.py"))
    _check(str(info.getMenuPathAsString()) == "Tools->MCRIT", "script declares Tools > MCRIT")
    gui.edt(lambda: script_service.runScript("MCRIT.py", None))
    from mcrit_plugin.ghidra.controller import _registry

    controller = _wait(lambda: next(iter(_registry().values()), None), "MCRIT controller", 120)
    session = _wait(lambda: controller.session_for(program), "MCRIT session", 60)
    backend = session.cc.backend
    main = session.main_widget
    _wait(
        lambda: "successful" in session.local_widget.label_activity.text(),
        "connection check",
        30,
    )
    _check(True, "MCRIT window open and connected")
    pressed_tab = gui.press_tab(main.tabs)
    _wait(lambda: main.tabs.getSelectedIndex() == pressed_tab, "tab selected by a click", 10)
    _check(True, "clicking a tab header selects it")
    gui.shot("opened")

    # convert an unknown sample: family and version are asked for
    gui.later(main._onConvertSmdaButtonClicked)
    dialog = gui.window("Provide additional information about the sample", 180)
    fields = gui.find(dialog, "JTextField")
    gui.edt(lambda: fields[0].setText(FAMILY))
    gui.edt(lambda: fields[1].setText(VERSION))
    gui.shot("family_dialog")
    gui.click(dialog, "OK")
    _wait(lambda: session.local_smda_report and not main._building, "conversion", 120)
    report = session.local_smda_report
    _check(report.family == FAMILY and report.version == VERSION, "family and version applied")
    _check(session.remote_sample_id is None, "sample is new to the server")

    gui.edt(main._onUploadSmdaButtonClicked)
    _wait(
        lambda: session.remote_sample_id is not None and main.uploadSmdaAction.isEnabled(),
        "upload",
        120,
    )
    _check(main.getMatchResultAction.isEnabled(), "upload enables matching")
    client = session.mcrit_interface.mcrit_client
    _wait(
        lambda: client.getFunctionsBySampleId(session.remote_sample_id),
        "server indexed the upload",
        args.timeout,
    )

    gui.later(main._onGetMatchResultButtonClicked)
    gui.click(gui.window("Remote Match Results"), "Create New Matching Job")
    _wait(
        lambda: any(
            job.finished_at for job in session.mcrit_interface.queryJobs(session.remote_sample_id)
        ),
        "matching job finished",
        args.timeout,
    )
    gui.later(main._onGetMatchResultButtonClicked)
    dialog = gui.window("Remote Match Results")
    gui.shot("result_dialog")
    gui.click(dialog, "Select Result")
    _wait(lambda: session.matching_report is not None, "matching result", 120)
    _check(True, "matching result loaded through the dialog")
    if args.reference_sha256:
        reference = client.getSampleBySha256(args.reference_sha256)
        _check(
            reference is not None
            and any(
                match.sample_id == reference.sample_id
                for match in session.matching_report.sample_matches
            ),
            "query sample matches the reference sample",
        )

    # live Function Scope: a cursor move queries the function
    function_widget = session.function_match_widget
    gui.edt(lambda: function_widget.cb_activate_live_tracking.doClick())
    gui.edt(lambda: main.setTabFocus(function_widget.name))
    target = max(report.getFunctions(), key=lambda function: function.num_instructions)
    gui.edt(lambda: backend.jump_to(target.offset))
    _wait(lambda: function_widget.table_function_matches.rows, "live function query", 120)
    _check(
        session.current_function == target.offset,
        "cursor move reached the Function Scope",
    )
    gui.shot("function_scope")

    # remote CFG of the best match, with the local blocks tinted
    modification = program.getModificationNumber()
    gui.edt(lambda: function_widget._onFunctionMatchClicked(0, 0, 2))
    _wait(
        lambda: "Opened the graph" in session.local_widget.label_activity.text(),
        "remote CFG",
        120,
    )
    _wait(lambda: any("MCRIT CFG" in str(w.getTitle()) for w in gui.windows()), "graph", 60)
    _check(
        backend._colored and any(not m.getAddressSet().isEmpty() for m in backend._colored),
        "graph opened and matched local blocks tinted",
    )
    # the tint is a transient marker: no undo entry, nothing to save on close
    _check(
        program.getModificationNumber() == modification,
        "tinting left the program unmodified",
    )
    gui.shot("graph")

    block_widget = session.block_match_widget
    gui.edt(lambda: main.setTabFocus(block_widget.name))
    gui.edt(block_widget.queryCurrentBlock)
    _wait(lambda: block_widget.table_block_summary.rows, "block query", 120)
    _check(True, "Block Scope lists the function's blocks")
    gui.shot("block_scope")

    overview = session.function_widget
    gui.edt(lambda: main.setTabFocus(overview.name))
    gui.edt(lambda: overview.fetchLabels(force=True))
    _wait(lambda: overview.b_fetch_labels.isEnabled() and overview.rows, "label fetch", 120)
    unnamed_with_labels = [
        row.offset
        for row in overview.rows
        if row.label_entries and backend.has_default_function_name(row.offset)
    ]
    gui.edt(overview.importSelectedLabels)
    _check(
        all(not backend.has_default_function_name(offset) for offset in unnamed_with_labels),
        f"labels imported for {len(unnamed_with_labels)} unnamed functions",
    )
    gui.shot("overview")

    sample_widget = session.sample_widget
    gui.edt(lambda: main.setTabFocus(sample_widget.name))
    _check(sample_widget.table_best_family_matches.rows, "Sample Match Summary filled")

    gui.later(main._onBuildYaraStringButtonClicked)
    dialog = gui.window("YARA String Builder")
    text = str(gui.find(dialog, "JTextArea")[0].getText())
    _check(text.startswith("rule ") and "condition:" in text, "YARA builder made a rule")
    gui.shot("yara")
    gui.click(dialog, "OK")

    # what the PyGhidra console's Reset does to the modules MCRIT imported; loading LIEF again
    # would abort the process, so the export below only passes when they are handed back
    lief_before = sys.modules.get("lief")
    for name in [n for n in sys.modules if n.partition(".")[0] in ("mcrit_plugin", "smda", "lief")]:
        del sys.modules[name]
    _check(
        importlib.import_module("lief") is lief_before,
        "after a console Reset, MCRIT gets its loaded modules back",
    )

    with tempfile.TemporaryDirectory() as export_dir:
        export_path = os.path.join(export_dir, "export.smda")
        backend.ask_save_file = lambda _name, _prompt: export_path
        gui.edt(main._onExportSmdaButtonClicked)
        _wait(lambda: os.path.exists(export_path) and os.path.getsize(export_path), "export", 120)
        time.sleep(1)
        with open(export_path) as handle:
            exported = json.load(handle)
        _check(exported["metadata"]["family"] == FAMILY, "export carries the sample's family")

    # a second program in the same tool shows the placeholder until MCRIT is opened for it
    copy = gui.edt(lambda: program_manager.openProgram(data.getFile("/" + COPY_NAME)))
    _wait(lambda: controller.active_key is None, "placeholder for the copy", 30)
    _check(controller.session_for(copy) is None, "other program shows the placeholder")
    gui.edt(lambda: program_manager.setCurrentProgram(program))
    _wait(lambda: controller.active_key == controller._program_key(program), "switch back", 30)

    # closing a program with renamed functions offers to upload them
    renamed = next(
        f.offset for f in report.getFunctions() if backend.has_default_function_name(f.offset)
    )
    with backend.mutation("Rename for the close prompt"):
        backend.set_function_name(renamed, "renamed_in_ghidra")
    gui.later(lambda: program_manager.closeProgram(program, True))
    prompt = gui.window("MCRIT")
    gui.shot("close_prompt")
    gui.click(prompt, "Yes")
    _wait(lambda: backend.closed and controller.session_for(program) is None, "session closed", 60)
    _check(True, "closing the program uploaded the renames and ended the session")
    RESULT["ok"] = True


def run_gui(args, workdir):
    from pyghidra.launcher import GuiPyGhidraLauncher

    sys.path.insert(0, str(REPO_ROOT))
    gui = Gui(args.screenshots)

    def steps():
        try:
            run_steps(args, gui)
            print("MCRIT_GHIDRA_GUI_INTEGRATION_OK", flush=True)
        except Exception:
            traceback.print_exc()
        finally:
            if not args.keep_open:
                # Ghidra keeps the JVM alive; end the process, and with it the throwaway profile
                shutil.rmtree(workdir, ignore_errors=True)
                os._exit(0 if RESULT["ok"] else 1)

    class Launcher(GuiPyGhidraLauncher):
        def _launch(self):
            # load MouseEvent before any window opens: its initializer takes the AWT lock, and on
            # a real display the X11 thread holds that lock while it waits for the class to load
            # for a pointer crossing, which deadlocks press_tab's first import
            from jpype import JClass

            JClass("java.awt.event.MouseEvent")
            threading.Thread(target=steps, daemon=True).start()
            super()._launch()

    launcher = Launcher(
        verbose=False, install_dir=Path(args.ghidra_dir) if args.ghidra_dir else None
    )
    launcher.args = [str(workdir / "project" / f"{PROJECT_NAME}.gpr")]
    launcher.start()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mcrit-server", default="http://127.0.0.1:8000/")
    parser.add_argument("--reference-sha256")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--ghidra-dir", help="Ghidra installation; defaults to GHIDRA_INSTALL_DIR")
    parser.add_argument("--screenshots", help="directory for a screenshot per step")
    parser.add_argument("--keep-open", action="store_true", help="leave Ghidra running at the end")
    parser.add_argument("--workdir", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--prepare-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.input = args.input.resolve()

    if args.prepare_only:
        prepare(args.input, args.workdir)
        return 0
    from mcrit_plugin.core.config import PLUGIN_ROOT

    if (Path(PLUGIN_ROOT) / "config_override.json").exists():
        raise RuntimeError("config_override.json would override the test settings; move it aside")
    if args.screenshots:
        os.makedirs(args.screenshots, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="mcrit-ghidra-gui-"))
    try:
        # a throwaway profile: Ghidra keeps its settings under XDG_CONFIG_HOME on Linux
        os.environ["XDG_CONFIG_HOME"] = str(workdir / "config")
        os.environ["XDG_CACHE_HOME"] = str(workdir / "cache")
        subprocess.run(
            [
                sys.executable,
                __file__,
                "--prepare-only",
                "--workdir",
                str(workdir),
                "--input",
                str(args.input),
            ]
            + (["--ghidra-dir", args.ghidra_dir] if args.ghidra_dir else []),
            check=True,
        )
        _accept_first_run_dialogs(workdir / "config")
        run_gui(args, workdir)
    finally:
        if not args.keep_open:
            shutil.rmtree(workdir, ignore_errors=True)
    return 0 if RESULT["ok"] else 1


def _accept_first_run_dialogs(config_home: Path):
    """Ghidra asks to accept its user agreement and shows tips on the first start of a profile.
    With XDG_CONFIG_HOME set, Ghidra names its folder ghidra or <user>-ghidra; both are covered."""
    for settings_dir in config_home.glob("*/ghidra_*"):
        preferences = settings_dir / "preferences"
        text = preferences.read_text() if preferences.exists() else ""
        additions = [
            line
            for line in ("USER_AGREEMENT=ACCEPT", "SHOW_TIPS=false")
            if line.split("=")[0] not in text
        ]
        preferences.write_text(text.rstrip("\n") + "\n" + "\n".join(additions) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
