/* ###
 * MCRIT plugin for Ghidra, GPL-3.0-only.
 */
package mcrit.ghidra;

import java.awt.Color;
import java.awt.Component;

import javax.swing.*;

import docking.widgets.table.GTable;
import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;

/** Builds and drives the tables of the MCRIT window. */
public final class McritTables {

	private McritTables() {
	}

	/**
	 * Ghidra's own cell look (font, selection, alternating rows), with the score tint the model
	 * gives a cell over it; choice cells get an arrow.
	 */
	static final class Renderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			JTable table = data.getTable();
			McritTableModel model = (McritTableModel) table.getModel();
			int sourceRow = model.sourceRow(data.getRowViewIndex());
			int modelColumn = data.getColumnModelIndex();
			if (model.isChoiceCell(sourceRow, modelColumn)) {
				setText(getText() + "  \u25BE");
			}
			setHorizontalAlignment(model.isCentered() ? SwingConstants.CENTER : SwingConstants.LEADING);
			Color background = model.getBackground(sourceRow, modelColumn);
			if (!data.isSelected() && background != null) {
				setBackground(background);
				Color foreground = model.getTintForeground();
				setForeground(foreground != null ? foreground : table.getForeground());
			}
			return this;
		}
	}

	/** A combo box over the choices of the row being edited. */
	static final class ChoiceEditor extends DefaultCellEditor {
		private final JComboBox<String> combo;

		@SuppressWarnings("unchecked")
		ChoiceEditor() {
			super(new JComboBox<String>());
			combo = (JComboBox<String>) getComponent();
			setClickCountToStart(1);
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value,
				boolean isSelected, int row, int column) {
			McritTableModel model = (McritTableModel) table.getModel();
			String[] choices = model.getChoices(model.sourceRow(row));
			combo.setModel(new DefaultComboBoxModel<>(choices != null ? choices : new String[0]));
			combo.setSelectedItem(value == null ? null : value.toString());
			SwingUtilities.invokeLater(() -> {
				if (combo.isShowing()) {
					combo.showPopup();
				}
			});
			return combo;
		}
	}

	/** A GTable: Ghidra's header with its sort marks and column menu, its copy and export actions. */
	public static final class Table extends GTable {
		private boolean ownPopup;

		Table(McritTableModel model) {
			super(model);
		}

		/** The panel shows a menu of its own on a context click; Ghidra's would open with it. */
		public void setOwnPopup(boolean ownPopup) {
			this.ownPopup = ownPopup;
		}

		@Override
		protected boolean supportsPopupActions() {
			return !ownPopup;
		}

		// fill the viewport while the columns fit, scroll sideways once they do not; a narrow
		// dock would otherwise squeeze every column to a few characters
		@Override
		public boolean getScrollableTracksViewportWidth() {
			return getPreferredSize().width < getParent().getWidth();
		}
	}

	public static Table create(McritTableModel model) {
		Table table = new Table(model);
		table.setDefaultRenderer(McritTableModel.Cell.class, new Renderer());
		table.setDefaultEditor(McritTableModel.Cell.class, new ChoiceEditor());
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setFillsViewportHeight(true);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		return table;
	}

	/** Select the whole row a source row is shown at and scroll it into view. */
	public static void selectModelRow(JTable table, int sourceRow) {
		int viewRow = ((McritTableModel) table.getModel()).shownRow(sourceRow);
		if (viewRow < 0) {
			return;
		}
		table.setRowSelectionInterval(viewRow, viewRow);
		table.scrollRectToVisible(table.getCellRect(viewRow, 0, true));
	}

	/** Size the columns to their header and widest cell, up to a cap. */
	public static void fitColumns(JTable table, int maxWidth) {
		for (int column = 0; column < table.getColumnCount(); column++) {
			var header = table.getTableHeader().getDefaultRenderer()
					.getTableCellRendererComponent(table, table.getColumnName(column), false,
						false, -1, column);
			int width = header.getPreferredSize().width;
			int rows = Math.min(table.getRowCount(), 500);
			for (int row = 0; row < rows; row++) {
				Component cell = table.prepareRenderer(table.getCellRenderer(row, column), row,
					column);
				width = Math.max(width, cell.getPreferredSize().width);
			}
			table.getColumnModel().getColumn(column).setPreferredWidth(
				Math.min(width + 12, maxWidth));
		}
	}
}
