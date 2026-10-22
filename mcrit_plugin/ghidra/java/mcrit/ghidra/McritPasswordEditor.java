/* ###
 * MCRIT plugin for Ghidra, GPL-3.0-only.
 */
package mcrit.ghidra;

import java.awt.Component;
import java.beans.PropertyEditorSupport;

import javax.swing.JPasswordField;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Options editor that masks a string option, for the MCRITweb API token. The value is still
 * stored with the tool's options; this only keeps it off the screen.
 */
public class McritPasswordEditor extends PropertyEditorSupport {

	/**
	 * Register a masked string option. Done from Java: Options' PropertyEditor overload looks up
	 * its caller on the Java stack, which a call straight from Python does not have.
	 */
	public static void register(Options options, String name, String defaultValue,
			String description) {
		options.registerOption(name, OptionType.STRING_TYPE, defaultValue, null, description,
			() -> new McritPasswordEditor());
	}

	private final JPasswordField field = new JPasswordField(30);
	private boolean updating;

	public McritPasswordEditor() {
		field.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				changed();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				changed();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				changed();
			}
		});
	}

	private void changed() {
		if (!updating) {
			super.setValue(new String(field.getPassword()));
		}
	}

	@Override
	public void setValue(Object value) {
		super.setValue(value);
		updating = true;
		try {
			field.setText(value == null ? "" : value.toString());
		}
		finally {
			updating = false;
		}
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public Component getCustomEditor() {
		return field;
	}
}
