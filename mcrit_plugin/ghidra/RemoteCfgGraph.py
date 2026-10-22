"""The CFG of a remote SMDA function as a Ghidra AttributedGraph, for the default graph display."""

VERTEX_TYPE = "Block"
EDGE_FALL_THROUGH = "Fall-Through"
EDGE_TAKEN = "Conditional-Jump"
EDGE_UNCONDITIONAL = "Unconditional-Jump"
EDGE_INDIRECT = "Computed"
EDGE_TYPES = [EDGE_FALL_THROUGH, EDGE_TAKEN, EDGE_UNCONDITIONAL, EDGE_INDIRECT]
# Ghidra's code flow graphs color edges like this; the listing's own CFG uses the same scheme
EDGE_COLORS = {
    EDGE_FALL_THROUGH: "#4682B4",
    EDGE_TAKEN: "#2E8B57",
    EDGE_UNCONDITIONAL: "#1E90FF",
    EDGE_INDIRECT: "#B22222",
}
COLOR_KEY = "Color"
LABEL_KEY = "Code"
MAX_LINE = 60


def _edge_types(block, targets):
    """Classify a block's outgoing edges: the fall-through of a two-way branch and its target."""
    if len(targets) == 1:
        return {targets[0]: EDGE_UNCONDITIONAL}
    if len(targets) != 2:
        return {target: EDGE_INDIRECT for target in targets}
    last_instruction = list(block.getInstructions())[-1]
    fall_through = last_instruction.offset + len(last_instruction.bytes) // 2
    return {
        target: EDGE_FALL_THROUGH if target == fall_through else EDGE_TAKEN for target in targets
    }


def block_lines(smda_function, block):
    """The text lines a block shows: address, mnemonic and operands, API names for API calls."""
    lines = []
    for instruction in block.getInstructions():
        api = smda_function.apirefs.get(instruction.offset, "")
        operands = f"[{api}]" if api else instruction.operands
        line = f"{instruction.offset:x}  {instruction.mnemonic:<6} {operands}"
        if len(line) > MAX_LINE:
            line = line[: MAX_LINE - 3] + "..."
        lines.append(line)
    return lines


def block_label(smda_function, block):
    """Plain text, one line per instruction: the graph display escapes labels into HTML itself
    (HTMLUtilities.toLiteralHTML), keeping line breaks and spaces."""
    return "\n".join(block_lines(smda_function, block))


def edges(smda_function):
    """(source, target, edge type) for every edge between blocks of the function."""
    blocks = {block.offset: block for block in smda_function.getBlocks()}
    result = []
    for source, targets in smda_function.blockrefs.items():
        if source not in blocks:
            continue
        targets = [target for target in targets if target in blocks]
        for target, edge_type in _edge_types(blocks[source], targets).items():
            result.append((source, target, edge_type))
    return result


def build_graph(title, smda_function, coloring):
    """(AttributedGraph, GraphDisplayOptions) for smda_function; coloring maps block offset ->
    0xRRGGBB."""
    from ghidra.service.graph import (
        AttributedGraph,
        GraphDisplayOptions,
        GraphLabelPosition,
        GraphType,
        VertexShape,
    )
    from java.util import Arrays

    graph_type = GraphType(
        "MCRIT Remote CFG",
        "Control flow graph of a function stored on the MCRIT server",
        Arrays.asList(VERTEX_TYPE),
        Arrays.asList(*EDGE_TYPES),
    )
    graph = AttributedGraph(title, graph_type, title)
    vertices = {}
    for block in smda_function.getBlocks():
        vertex = graph.addVertex("0x%x" % block.offset, "0x%x" % block.offset)
        vertex.setVertexType(VERTEX_TYPE)
        vertex.setAttribute(LABEL_KEY, block_label(smda_function, block))
        if block.offset in coloring:
            vertex.setAttribute(COLOR_KEY, "#%06x" % coloring[block.offset])
        vertices[block.offset] = vertex
    for source, target, edge_type in edges(smda_function):
        edge = graph.addEdge(vertices[source], vertices[target])
        edge.setEdgeType(edge_type)

    options = GraphDisplayOptions(graph_type)
    options.setDefaultVertexShape(VertexShape.RECTANGLE)
    from java.awt import Color, Font

    # a str selects the overloads that take a theme color id, not a hex value
    options.setDefaultVertexColor(Color.decode("#D3D3D3"))
    options.setVertexLabelOverrideAttributeKey(LABEL_KEY)
    options.setVertexColorOverrideAttributeKey(COLOR_KEY)
    options.setLabelPosition(GraphLabelPosition.CENTER)
    options.setFavoredEdgeType(EDGE_FALL_THROUGH)
    options.setFont(Font(Font.MONOSPACED, Font.PLAIN, 12))
    for edge_type, color in EDGE_COLORS.items():
        options.setEdgeColor(edge_type, Color.decode(color))
    return graph, options
