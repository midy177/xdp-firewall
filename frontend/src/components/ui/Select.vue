<template>
  <select class="ui-input" v-bind="$attrs" :value="modelValue ?? ''" @change="onChange">
    <slot />
  </select>
</template>

<script setup lang="ts">
defineProps<{
  modelValue?: string | number | null;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: string];
}>();

function onChange(event: Event) {
  emit("update:modelValue", (event.target as HTMLSelectElement).value);
}
</script>
