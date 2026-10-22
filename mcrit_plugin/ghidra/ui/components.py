"""Swing building blocks for the panels: labels, controls, and a vertical layout helper."""

import html

from mcrit_plugin.ghidra import swing


def wrapped(text):
    """HTML for a label that wraps long text instead of widening the window."""
    return "<html>%s</html>" % html.escape(str(text))


class Label:
    """A JLabel that wraps its text; set_text is safe from any thread."""

    def __init__(self, text="", wrap=True):
        from javax.swing import JLabel

        self.wrap = wrap
        self.component = JLabel()
        self._text = ""
        self.setText(text)

    def setText(self, text):
        self._text = str(text)
        value = wrapped(self._text) if self.wrap else self._text
        if swing.is_swing_thread():
            self.component.setText(value)
        else:
            swing.invoke_later(lambda: self.component.setText(value))

    def text(self):
        return self._text


def checkbox(text, checked=False, enabled=True, on_click=None):
    from javax.swing import JCheckBox

    box = JCheckBox(text, bool(checked))
    box.setEnabled(enabled)
    if on_click is not None:
        listener = swing.ActionListener(lambda _event: on_click())
        box.addActionListener(listener)
    return box


def button(text, on_click=None, enabled=True, icon=None, tooltip=None):
    from javax.swing import JButton

    widget = JButton(text) if icon is None else JButton(text, icon)
    widget.setEnabled(enabled)
    if tooltip:
        widget.setToolTipText(tooltip)
    if on_click is not None:
        widget.addActionListener(swing.ActionListener(lambda _event: on_click()))
    return widget


def scrolling_tabs():
    """A JTabbedPane with its tabs in one scrolling row, so a narrow dock does not wrap them.

    The scroll layout paints the tabs on a child panel that has no mouse listener of its own, so
    a click falls through to the tabbed pane's handler. Ghidra's DockableComponent adds a listener
    to every component in a provider, which makes the panel the click's target and the tabs
    unclickable. The panel therefore selects the pressed tab itself; it is recreated with the UI,
    e.g. on a theme change, so the listener is installed again then.
    """
    from javax.swing import JTabbedPane, JViewport, SwingUtilities

    tabs = JTabbedPane()
    tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)

    def pressed(event):
        if not SwingUtilities.isLeftMouseButton(event):
            return
        point = SwingUtilities.convertPoint(event.getComponent(), event.getPoint(), tabs)
        index = tabs.indexAtLocation(int(point.getX()), int(point.getY()))
        if index >= 0 and tabs.isEnabledAt(index):
            tabs.setSelectedIndex(index)

    listener = swing.MouseListener(on_press=pressed)

    def install(_event=None):
        for child in tabs.getComponents():
            if isinstance(child, JViewport) and child.getView() is not None:
                view = child.getView()
                if listener not in list(view.getMouseListeners()):
                    view.addMouseListener(listener)

    install()
    tabs.addPropertyChangeListener("UI", swing.PropertyChangeListener(install))
    return tabs


class Spinner:
    """An integer JSpinner with a value() and a quiet setRange, like the Qt spin boxes."""

    def __init__(self, minimum, maximum, value, on_change=None):
        from javax.swing import JSpinner, SpinnerNumberModel

        # config_override.json values reach here unclamped, and the model rejects one out of range
        value = max(int(minimum), min(int(maximum), int(value)))
        self.model = SpinnerNumberModel(value, int(minimum), int(maximum), 1)
        self.component = JSpinner(self.model)
        self._on_change = on_change
        self._quiet = False
        self.component.addChangeListener(swing.ChangeListener(self._changed))

    def _changed(self, _event):
        if not self._quiet and self._on_change is not None:
            self._on_change()

    def value(self):
        return int(self.model.getNumber().intValue())

    def setRange(self, minimum, maximum, value=None):
        """Change range and value without calling on_change."""
        from java.lang import Integer

        self._quiet = True
        try:
            value = self.value() if value is None else value
            value = max(minimum, min(maximum, value))
            self.model.setMinimum(Integer(int(minimum)))
            self.model.setMaximum(Integer(int(maximum)))
            self.model.setValue(Integer(int(value)))
        finally:
            self._quiet = False

    def setValue(self, value):
        from java.lang import Integer

        self.model.setValue(Integer(int(value)))


def separator():
    from javax.swing import JSeparator

    return JSeparator()


def row(*components, glue=True):
    """Components side by side, left aligned."""
    from javax.swing import Box, BoxLayout, JPanel

    panel = JPanel()
    panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
    for index, component in enumerate(components):
        if index:
            panel.add(Box.createHorizontalStrut(8))
        panel.add(component)
    if glue:
        panel.add(Box.createHorizontalGlue())
    return align_left(panel)


def align_left(component):
    from java.awt import Component

    component.setAlignmentX(Component.LEFT_ALIGNMENT)
    return component


def stack(*components, fill=()):
    """A vertical panel; components listed in fill take up the remaining height, the others keep
    their preferred height."""
    from java.awt import GridBagConstraints, GridBagLayout, Insets
    from javax.swing import JPanel

    panel = JPanel(GridBagLayout())
    for index, component in enumerate(components):
        constraints = GridBagConstraints()
        constraints.gridx = 0
        constraints.gridy = index
        constraints.weightx = 1.0
        constraints.anchor = GridBagConstraints.NORTHWEST
        constraints.insets = Insets(2, 4, 2, 4)
        if component in fill:
            constraints.fill = GridBagConstraints.BOTH
            constraints.weighty = 1.0
        else:
            constraints.fill = GridBagConstraints.HORIZONTAL
            constraints.weighty = 0.0
        panel.add(component, constraints)
    if not fill:
        # keep everything at the top
        from javax.swing import Box

        constraints = GridBagConstraints()
        constraints.gridy = len(components)
        constraints.weighty = 1.0
        panel.add(Box.createVerticalGlue(), constraints)
    return panel


def grid(pairs):
    """Two columns of (label, value) components."""
    from java.awt import GridBagConstraints, GridBagLayout, Insets
    from javax.swing import JPanel

    panel = JPanel(GridBagLayout())
    for index, (left, right) in enumerate(pairs):
        for column, component in enumerate((left, right)):
            constraints = GridBagConstraints()
            constraints.gridx = column
            constraints.gridy = index
            constraints.anchor = GridBagConstraints.WEST
            constraints.fill = GridBagConstraints.HORIZONTAL
            constraints.weightx = 0.0 if column == 0 else 1.0
            constraints.insets = Insets(1, 0, 1, 12 if column == 0 else 0)
            panel.add(component, constraints)
    return panel


def load_icon(path, size=20):
    """An ImageIcon scaled to size pixels, or None when the file cannot be read. The icons are
    one-colour glyphs, drawn here in the theme's label colour so they show on dark themes too."""
    try:
        from java.awt import AlphaComposite, Image
        from java.awt.image import BufferedImage
        from javax.swing import ImageIcon, UIManager

        icon = ImageIcon(str(path))
        if icon.getIconWidth() <= 0:
            return None
        image = icon.getImage()
        color = UIManager.getColor("Label.foreground")
        if color is not None:
            width, height = icon.getIconWidth(), icon.getIconHeight()
            tinted = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
            graphics = tinted.createGraphics()
            graphics.drawImage(image, 0, 0, None)
            graphics.setComposite(AlphaComposite.SrcIn)
            graphics.setColor(color)
            graphics.fillRect(0, 0, width, height)
            graphics.dispose()
            image = tinted
        return ImageIcon(image.getScaledInstance(size, size, Image.SCALE_SMOOTH))
    except Exception:
        return None


def copy_to_clipboard(text):
    from java.awt import Toolkit
    from java.awt.datatransfer import StringSelection

    selection = StringSelection(text)
    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection)
