/*
  Copyright: (c) 2019, Guilherme Francescon Cittolin <gfcittolin@gmail.com>
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include "common.h"

#define PNT_FLASHLED_TIMEWAIT 3000
#define PNT_FLASHLED_COUNT 1

#define TIME_DIFF_MS(s, e) ((e.tv_sec - s.tv_sec) * 1e3 + (e.tv_nsec - s.tv_nsec) / 1e6)

int pnt_flashled(int argc, char **argv);