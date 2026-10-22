/* ###
 * MCRIT plugin for Ghidra, GPL-3.0-only.
 */
package mcrit.ghidra;

import java.awt.Color;

import javax.swing.table.AbstractTableModel;

/**
 * Read-only rows of the MCRIT tables, filled from Python in one call per refresh.
 *
 * Each cell has the text it shows and the value it sorts by, so offsets shown in hex sort as
 * numbers. Model rows stay in the order Python filled them in; a RowSorter orders the view. One
 * column may hold per-row choices, edited with a combo box (the Function Overview's labels).
 */
public class McritTableModel extends AbstractTableModel {

	/** A cell: shown as its text, sorted by its key (numbers before text, text without case). */
	public static final class Cell implements Comparable<Cell> {
		private final String text;
		private final Object key;

		public Cell(String text, Object key) {
			this.text = text == null ? "" : text;
			this.key = key == null ? this.text : key;
		}

		public String getText() {
			return text;
		}

		public Object getKey() {
			return key;
		}

		@Override
		public int compareTo(Cell other) {
			if (key instanceof Number a && other.key instanceof Number b) {
				return Double.compare(a.doubleValue(), b.doubleValue());
			}
			if (key instanceof Number) {
				return -1;
			}
			if (other.key instanceof Number) {
				return 1;
			}
			return key.toString().compareToIgnoreCase(other.key.toString());
		}

		@Override
		public String toString() {
			return text;
		}
	}

	private String[] headers = new String[0];
	private Cell[][] rows = new Cell[0][];
	private Color[] rowBackgrounds = new Color[0];
	private Color tintForeground;
	private int choiceColumn = -1;
	private String[][] choices = new String[0][];
	private Color[] choiceBackgrounds = new Color[0];
	private boolean centered;

	/**
	 * Replace all rows. texts and keys are row-major; backgrounds may be null, as may any entry.
	 * The table keeps its sort order when the headers stay the same.
	 */
	public void reset(String[] newHeaders, String[][] texts, Object[][] keys, Color[] backgrounds,
			Color foreground) {
		boolean sameHeaders = java.util.Arrays.equals(headers, newHeaders);
		headers = newHeaders;
		rows = new Cell[texts.length][];
		for (int row = 0; row < texts.length; row++) {
			rows[row] = new Cell[texts[row].length];
			for (int column = 0; column < texts[row].length; column++) {
				Object key = keys != null && keys[row] != null ? keys[row][column] : null;
				rows[row][column] = new Cell(texts[row][column], key);
			}
		}
		rowBackgrounds = backgrounds != null ? backgrounds : new Color[texts.length];
		tintForeground = foreground;
		choiceColumn = -1;
		choices = new String[texts.length][];
		choiceBackgrounds = new Color[texts.length];
		if (sameHeaders) {
			fireTableDataChanged();
		}
		else {
			fireTableStructureChanged();
		}
	}

	/** Offer per-row choices in one column; a row whose choices are null stays plain. */
	public void setChoices(int column, String[][] rowChoices, Color[] backgrounds) {
		choiceColumn = column;
		choices = rowChoices != null ? rowChoices : new String[rows.length][];
		choiceBackgrounds = backgrounds != null ? backgrounds : new Color[rows.length];
		fireTableDataChanged();
	}

	public void setCentered(boolean centered) {
		this.centered = centered;
	}

	public boolean isCentered() {
		return centered;
	}

	public String[] getChoices(int row) {
		return row < choices.length ? choices[row] : null;
	}

	public boolean isChoiceCell(int row, int column) {
		return column == choiceColumn && getChoices(row) != null;
	}

	/** Background of a cell, or null for the table's own. */
	public Color getBackground(int row, int column) {
		if (column == choiceColumn && row < choiceBackgrounds.length &&
			choiceBackgrounds[row] != null) {
			return choiceBackgrounds[row];
		}
		return row < rowBackgrounds.length ? rowBackgrounds[row] : null;
	}

	public Color getTintForeground() {
		return tintForeground;
	}

	public String getText(int row, int column) {
		return rows[row][column].getText();
	}

	@Override
	public int getRowCount() {
		return rows.length;
	}

	@Override
	public int getColumnCount() {
		return headers.length;
	}

	@Override
	public String getColumnName(int column) {
		return headers[column];
	}

	@Override
	public Class<?> getColumnClass(int column) {
		return Cell.class;
	}

	@Override
	public Object getValueAt(int row, int column) {
		return rows[row][column];
	}

	@Override
	public boolean isCellEditable(int row, int column) {
		return isChoiceCell(row, column);
	}

	@Override
	public void setValueAt(Object value, int row, int column) {
		if (!isChoiceCell(row, column) || value == null) {
			return;
		}
		String text = value.toString();
		rows[row][column] = new Cell(text, labelKey(text));
		fireTableCellUpdated(row, column);
	}

	/** A "score|label" choice sorts by score, the opt-out "-|-" below every score. */
	public static Object labelKey(String text) {
		int bar = text.indexOf('|');
		String score = bar < 0 ? text : text.substring(0, bar);
		try {
			return Integer.parseInt(score);
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}
}
