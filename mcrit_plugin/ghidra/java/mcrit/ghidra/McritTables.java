/* ###
 * MCRIT plugin for Ghidra, GPL-3.0-only.
 */
package mcrit.ghidra;

import java.awt.Color;
import java.awt.Component;
import java.util.List;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;

/** Builds and drives the tables of the MCRIT window. */
public final class McritTables {

	private McritTables() {
	}

	/** Shows a cell's text over the background the model gives it; choice cells get an arrow. */
	static final class Renderer extends DefaultTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean isSelected, boolean hasFocus, int row, int column) {
			McritTableModel model = (McritTableModel) table.getModel();
			int modelRow = table.convertRowIndexToModel(row);
			int modelColumn = table.convertColumnIndexToModel(column);
			String text = value == null ? "" : value.toString();
			if (model.isChoiceCell(modelRow, modelColumn)) {
				text = text + "  \u25BE";
			}
			super.getTableCellRendererComponent(table, text, isSelected, hasFocus, row, column);
			setHorizontalAlignment(model.isCentered() ? SwingConstants.CENTER : SwingConstants.LEADING);
			Color background = model.getBackground(modelRow, modelColumn);
			if (!isSelected) {
				if (background != null) {
					setBackground(background);
					Color foreground = model.getTintForeground();
					setForeground(foreground != null ? foreground : table.getForeground());
				}
				else {
					setBackground(table.getBackground());
					setForeground(table.getForeground());
				}
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
			String[] choices = model.getChoices(table.convertRowIndexToModel(row));
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

	public static JTable create(McritTableModel model) {
		JTable table = new JTable(model) {
			// fill the viewport while the columns fit, scroll sideways once they do not; a narrow
			// dock would otherwise squeeze every column to a few characters
			@Override
			public boolean getScrollableTracksViewportWidth() {
				return getPreferredSize().width < getParent().getWidth();
			}
		};
		table.setDefaultRenderer(McritTableModel.Cell.class, new Renderer());
		table.setDefaultEditor(McritTableModel.Cell.class, new ChoiceEditor());
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setFillsViewportHeight(true);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		TableRowSorter<McritTableModel> sorter = new TableRowSorter<>(model);
		sorter.setSortsOnUpdates(true);
		table.setRowSorter(sorter);
		return table;
	}

	/** Sort by one column, as a header click would. */
	public static void sortBy(JTable table, int column, boolean ascending) {
		RowSorter<?> sorter = table.getRowSorter();
		if (sorter != null && column >= 0 && column < table.getModel().getColumnCount()) {
			sorter.setSortKeys(List.of(new RowSorter.SortKey(column,
				ascending ? SortOrder.ASCENDING : SortOrder.DESCENDING)));
		}
	}

	/** Select a whole row given by its model index and scroll it into view. */
	public static void selectModelRow(JTable table, int modelRow) {
		if (modelRow < 0 || modelRow >= table.getModel().getRowCount()) {
			return;
		}
		int viewRow = table.convertRowIndexToView(modelRow);
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
