/* ###
 * MCRIT plugin for Ghidra, GPL-3.0-only.
 */
package mcrit.ghidra;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.TableSortState;

/**
 * Read-only rows of the MCRIT tables, filled from Python in one call per refresh.
 *
 * Each cell has the text it shows and the value it sorts by, so offsets shown in hex sort as
 * numbers. It is one of Ghidra's sorted models, so a GTable sorts it from its header as it does
 * Ghidra's own tables. Its row objects hold the positions Python filled the rows in at ("source
 * rows"), which is what Python addresses a row by; the methods of TableModel take the row as
 * shown. One column may hold per-row choices, edited with a combo box (the Function
 * Overview's labels).
 */
public class McritTableModel extends AbstractSortedTableModel<McritTableModel.Row> {

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
	/**
	 * A row of one fill. Each fill makes new ones: a GTable keeps its selection on the row object
	 * across a data change, and would select whatever a refill put at that source row.
	 */
	public static final class Row {
		private final int sourceRow;

		Row(int sourceRow) {
			this.sourceRow = sourceRow;
		}
	}

	// the rows in the order they are shown; Ghidra sorts this list in place
	private List<Row> order = new ArrayList<>();
	private Color[] rowBackgrounds = new Color[0];
	private Color tintForeground;
	private int choiceColumn = -1;
	private String[][] choices = new String[0][];
	private Color[] choiceBackgrounds = new Color[0];
	private boolean centered;

	public McritTableModel() {
		// rows come in a meaningful order, best matches first, until a header is clicked
		setDefaultTableSortState(TableSortState.createUnsortedSortState());
	}

	@Override
	public String getName() {
		return "MCRIT";
	}

	@Override
	public List<Row> getModelData() {
		return order;
	}

	@Override
	public Object getColumnValueForRow(Row row, int column) {
		return rows[row.sourceRow][column];
	}

	@Override
	public boolean isSortable(int column) {
		return true;
	}

	/** The source row shown at a row of the table, or -1. */
	public int sourceRow(int row) {
		return row >= 0 && row < order.size() ? order.get(row).sourceRow : -1;
	}

	/** The row of the table a source row is shown at, or -1. */
	public int shownRow(int sourceRow) {
		for (int row = 0; row < order.size(); row++) {
			if (order.get(row).sourceRow == sourceRow) {
				return row;
			}
		}
		return -1;
	}

	/** Sort by one column, as a header click would. */
	public void sortBy(int column, boolean ascending) {
		if (column >= 0 && column < headers.length) {
			setTableSortState(TableSortState.createDefaultSortState(column, ascending));
		}
	}

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
		order = new ArrayList<>(texts.length);
		for (int row = 0; row < texts.length; row++) {
			order.add(new Row(row));
		}
		if (sameHeaders) {
			fireTableDataChanged();
		}
		else {
			setDefaultTableSortState(TableSortState.createUnsortedSortState());
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

	// the methods below take a source row

	public String[] getChoices(int row) {
		return row >= 0 && row < choices.length ? choices[row] : null;
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
	public boolean isCellEditable(int row, int column) {
		return isChoiceCell(sourceRow(row), column);
	}

	@Override
	public void setValueAt(Object value, int row, int column) {
		int source = sourceRow(row);
		if (!isChoiceCell(source, column) || value == null) {
			return;
		}
		String text = value.toString();
		if (!java.util.Arrays.asList(getChoices(source)).contains(text)) {
			return;
		}
		rows[source][column] = new Cell(text, labelKey(text));
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
