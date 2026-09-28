import math


class ThemeRole:
    """Plugin color roles a Backend may remap onto the host disassembler's own theme."""

    NEUTRAL = "neutral"
    BLUE = "blue"
    CYAN = "cyan"
    GREEN = "green"
    YELLOW = "yellow"
    ORANGE = "orange"
    RED = "red"
    MAGENTA = "magenta"
    CURRENT = "current"
    TEXT_ON_TINT = "text_on_tint"


class ScoreColorProvider(object):
    frequency_color_map = {
        # white
        0: (ThemeRole.NEUTRAL, (0xFF, 0xFF, 0xFF)),
        # blue
        1: (ThemeRole.BLUE, (0x10, 0x7F, 0xFC)),
        # light blue
        2: (ThemeRole.CYAN, (0x22, 0xFE, 0xFD)),
        # green
        3: (ThemeRole.GREEN, (0x1F, 0xFE, 0x28)),
        # green yellow: (0xc1, 0xfe, 0x2f)
        # yellow
        4: (ThemeRole.YELLOW, (0xFF, 0xFF, 0x35)),
        # light orange: (0xfe, 0xc1, 0x2c)
        # orange
        5: (ThemeRole.ORANGE, (0xFE, 0x82, 0x25)),
        # light red:
        # 6: (0xfd, 0x46, 0x21),
        # red
        6: (ThemeRole.RED, (0xFD, 0x1A, 0x20)),
        # violet
        7: (ThemeRole.MAGENTA, (0xB4, 0x00, 0xFF)),
    }

    matching_color_map_50 = {
        # white
        0: (ThemeRole.NEUTRAL, (0xFF, 0xFF, 0xFF)),
        # dark blue
        1: (ThemeRole.BLUE, (0x00, 0x45, 0xBA)),
        # blue
        2: (ThemeRole.BLUE, (0x00, 0x80, 0xFF)),
        # light blue
        3: (ThemeRole.CYAN, (0x22, 0xFE, 0xFD)),
        # green
        4: (ThemeRole.GREEN, (0x1F, 0xFE, 0x28)),
        # yellow
        5: (ThemeRole.YELLOW, (0xFF, 0xFF, 0x35)),
        # orange
        6: (ThemeRole.ORANGE, (0xFE, 0x82, 0x25)),
        # red
        7: (ThemeRole.RED, (0xFD, 0x1A, 0x20)),
    }

    def _calculateLogScore(self, cluster_size):
        if cluster_size == 0:
            return 0
        elif cluster_size == 1:
            return 1
        else:
            return 1 + int(math.log(cluster_size, 2))

    def _adjustOpacity(self, tup, opacity=1):
        return tuple(int(255 - opacity * (255 - e)) for e in tup)

    def roleColor(self, role, default):
        """RGB tuple for a role, remapped by the backend when it themes that role."""
        if self.backend is None:
            return default
        return self.backend.theme_color(role, default)

    def textOnTintColor(self):
        """RGB tuple for text drawn on a tinted row, or None to keep the widget's own color."""
        return self.roleColor(ThemeRole.TEXT_ON_TINT, (0, 0, 0))

    def _mapColor(self, color_map, level, opacity=1):
        role, default = color_map[level]
        return self._adjustOpacity(self.roleColor(role, default), opacity)

    def frequencyToColor(self, count, opacity=1):
        frequency = self._calculateLogScore(count)
        if frequency not in self.frequency_color_map:
            frequency = max(self.frequency_color_map)
        return self._mapColor(self.frequency_color_map, frequency, opacity)

    def scoreToColor(self, score, opacity=1):
        if score > 100:
            return self._mapColor(self.matching_color_map_50, 1, opacity)
        elif score == 100:
            return self._mapColor(self.matching_color_map_50, 2, opacity)
        elif score >= 90:
            return self._mapColor(self.matching_color_map_50, 3, opacity)
        elif score >= 80:
            return self._mapColor(self.matching_color_map_50, 4, opacity)
        elif score >= 70:
            return self._mapColor(self.matching_color_map_50, 5, opacity)
        elif score >= 60:
            return self._mapColor(self.matching_color_map_50, 6, opacity)
        elif score >= 50:
            return self._mapColor(self.matching_color_map_50, 7, opacity)
        return self._mapColor(self.frequency_color_map, 0)

    def uniqueScoreToColor(self, score, opacity=0.4):
        if score is not None and score > 0:
            return self.scoreToColor(60, opacity=opacity)
        return self._mapColor(self.frequency_color_map, 0)

    def __init__(self, backend=None) -> None:
        self.backend = backend
