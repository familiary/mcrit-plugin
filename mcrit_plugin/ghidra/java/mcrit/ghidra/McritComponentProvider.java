/* ###
 * MCRIT plugin for Ghidra, GPL-3.0-only.
 */
package mcrit.ghidra;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

/**
 * Dockable window hosting the Swing component the Python side of the MCRIT plugin builds.
 *
 * PyGhidra implements Java interfaces in Python but cannot extend Java classes, and Ghidra has no
 * concrete provider that takes a component, so this is the one piece of Java the plugin needs.
 */
public class McritComponentProvider extends ComponentProviderAdapter {

	/** Visibility callbacks, implemented in Python. */
	public interface Listener {
		void shown();

		void hidden();
	}

	private final JComponent component;
	private Listener listener;

	public McritComponentProvider(PluginTool tool, String name, String owner, JComponent component,
			Icon icon) {
		super(tool, name, owner);
		this.component = component;
		if (icon != null) {
			setIcon(icon);
		}
		setTitle(name);
		setDefaultWindowPosition(WindowPosition.RIGHT);
		setWindowMenuGroup("MCRIT");
		addToTool();
	}

	public void setListener(Listener listener) {
		this.listener = listener;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void componentShown() {
		if (listener != null) {
			listener.shown();
		}
	}

	@Override
	public void componentHidden() {
		if (listener != null) {
			listener.hidden();
		}
	}
}
