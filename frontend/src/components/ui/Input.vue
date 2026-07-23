<template>
  <input class="ui-input" v-bind="$attrs" :value="modelValue ?? ''" @input="onInput" />
</template>

<script setup lang="ts">
const props = defineProps<{
  modelValue?: string | number | null;
  modelModifiers?: Record<string, boolean>;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: string | number];
}>();

function onInput(event: Event) {
  const value = (event.target as HTMLInputElement).value;
  if (props.modelModifiers?.number && value !== "") {
    emit("update:modelValue", Number(value));
    return;
  }
  emit("update:modelValue", value);
}
</script>
