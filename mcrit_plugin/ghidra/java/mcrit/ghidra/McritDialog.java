/* ###
 * MCRIT plugin for Ghidra, GPL-3.0-only.
 */
package mcrit.ghidra;

import java.awt.Component;

import javax.swing.JButton;
import javax.swing.JComponent;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;

/**
 * A modal Ghidra dialog around the body and buttons the Python side builds, so the MCRIT dialogs
 * get Ghidra's dialog frame, button row, Escape handling and placement over the tool.
 *
 * PyGhidra cannot extend Java classes, and DialogComponentProvider's way in is protected.
 */
public class McritDialog extends DialogComponentProvider {

	public McritDialog(String title) {
		// modal, without a status line or a task monitor
		super(title, true, false, true, false);
	}

	public void setBody(JComponent body) {
		addWorkPanel(body);
	}

	public void addDialogButton(JButton button) {
		addButton(button);
	}

	/** Show the dialog over the window of parent, or over the active window; returns when it closed. */
	public void showOver(Component parent) {
		DockingWindowManager.showDialog(parent, this);
	}
}
