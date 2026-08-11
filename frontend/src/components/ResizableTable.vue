<template>
  <div ref="wrapperRef" class="resizable-table" :class="{ resizing: resizingColumn !== null }">
    <table ref="tableRef" :style="{ minWidth: tableMinWidth }">
      <colgroup v-if="widths.length > 0">
        <col v-for="(_, index) in widths" :key="index" :style="{ width: `${widths[index]}px` }" />
      </colgroup>
      <slot />
    </table>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";

const props = withDefaults(
  defineProps<{
    storageKey: string;
    defaultWidths?: number[];
    minWidth?: number;
  }>(),
  {
    defaultWidths: () => [],
    minWidth: 72,
  },
);

const tableRef = ref<HTMLTableElement | null>(null);
const wrapperRef = ref<HTMLDivElement | null>(null);
const widths = ref<number[]>([]);
const resizingColumn = ref<number | null>(null);
const cleanupHandlers: Array<() => void> = [];
let activeDragCleanup: (() => void) | null = null;
const tableMinWidth = computed(() => {
  const total = widths.value.reduce((sum, width) => sum + width, 0);
  return total > 0 ? `${total}px` : undefined;
});

function storageId() {
  return `xdp-firewall:table-widths:${props.storageKey}`;
}

function readSavedWidths(columnCount: number) {
  try {
    const parsed = JSON.parse(localStorage.getItem(storageId()) ?? "null");
    if (!Array.isArray(parsed) || parsed.length !== columnCount) {
      return null;
    }
    return parsed.map((value) => Math.max(Number(value) || props.minWidth, props.minWidth));
  } catch {
    return null;
  }
}

function saveWidths() {
  try {
    localStorage.setItem(storageId(), JSON.stringify(widths.value));
  } catch {
    // Column resizing should continue to work even if storage is unavailable.
  }
}

function clearHeaderHandlers() {
  while (cleanupHandlers.length > 0) {
    cleanupHandlers.pop()?.();
  }
}

function initialWidths(headers: HTMLTableCellElement[]) {
  const saved = readSavedWidths(headers.length);
  if (saved) {
    return saved;
  }
  return headers.map((header, index) => {
    const configured = props.defaultWidths[index];
    const measured = Math.ceil(header.getBoundingClientRect().width);
    return Math.max(configured || measured || props.minWidth, props.minWidth);
  });
}

function installHeaderHandlers() {
  clearHeaderHandlers();
  const table = tableRef.value;
  if (!table) {
    return;
  }
  const headers = Array.from(table.querySelectorAll<HTMLTableCellElement>("thead th"));
  if (headers.length === 0) {
    widths.value = [];
    return;
  }
  widths.value = initialWidths(headers);

  headers.forEach((header, index) => {
    header.classList.add("resizable-th");
    const handle = document.createElement("button");
    handle.type = "button";
    handle.className = "column-resizer";
    handle.setAttribute("aria-label", "Resize column");
    handle.title = "Resize column";
    header.appendChild(handle);

    const onPointerDown = (event: PointerEvent) => {
      event.preventDefault();
      event.stopPropagation();
      resizingColumn.value = index;
      const startX = event.clientX;
      const startWidth = widths.value[index] || props.minWidth;

      const onPointerMove = (moveEvent: PointerEvent) => {
        const nextWidth = Math.max(props.minWidth, Math.round(startWidth + moveEvent.clientX - startX));
        widths.value[index] = nextWidth;
      };
      const onPointerUp = () => {
        resizingColumn.value = null;
        saveWidths();
        document.removeEventListener("pointermove", onPointerMove);
        document.removeEventListener("pointerup", onPointerUp);
        document.removeEventListener("pointercancel", onPointerUp);
        activeDragCleanup = null;
      };

      document.addEventListener("pointermove", onPointerMove);
      document.addEventListener("pointerup", onPointerUp, { once: true });
      document.addEventListener("pointercancel", onPointerUp, { once: true });
      activeDragCleanup = onPointerUp;
    };

    handle.addEventListener("pointerdown", onPointerDown);
    cleanupHandlers.push(() => {
      handle.removeEventListener("pointerdown", onPointerDown);
      handle.remove();
      header.classList.remove("resizable-th");
    });
  });
}

onMounted(() => {
  nextTick(installHeaderHandlers);
});

onBeforeUnmount(() => {
  activeDragCleanup?.();
  clearHeaderHandlers();
});
</script>
